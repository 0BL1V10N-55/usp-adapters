package usp_sqs_files

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sqs"

	"github.com/refractionPOINT/go-uspclient"
	"github.com/refractionPOINT/go-uspclient/protocol"
	"github.com/refractionPOINT/usp-adapters/utils"
)

const (
	defaultWriteTimeout = 60 * 10
)

type SQSFilesAdapter struct {
	conf      SQSFilesConfig
	uspClient *uspclient.Client

	chFiles chan fileInfo

	// Every AWS call in this adapter signs with this one provider. Holding it
	// in a field rather than rebuilding static credentials at each call site
	// means an auth mode that does not use access_key/secret_key -- IAM Roles
	// Anywhere, say -- only has to change how this is constructed.
	awsCreds *credentials.Credentials

	// SQS
	awsConfig  *aws.Config
	awsSession *session.Session
	sqsClient  *sqs.SQS

	// S3. Cached per bucket: a single queue can carry events for buckets in
	// different regions, and a downloader is only valid for its bucket's
	// region. Guarded by s3Mutex because receiveEvents populates the map
	// while the processFiles goroutines read from it.
	s3Mutex     sync.Mutex
	downloaders map[string]*s3manager.Downloader

	ctx    context.Context
	isStop bool
	wg     sync.WaitGroup
}

type SQSFilesConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`

	// SQS specific
	AccessKey string `json:"access_key" yaml:"access_key"`
	SecretKey string `json:"secret_key,omitempty" yaml:"secret_key,omitempty"`
	QueueURL  string `json:"queue_url" yaml:"queue_url"`
	Region    string `json:"region" yaml:"region"`

	// S3 specific
	ParallelFetch     int    `json:"parallel_fetch" yaml:"parallel_fetch"`
	BucketPath        string `json:"bucket_path,omitempty" yaml:"bucket_path,omitempty"`
	FilePath          string `json:"file_path,omitempty" yaml:"file_path,omitempty"`
	IsDecodeObjectKey bool   `json:"is_decode_object_key,omitempty" yaml:"is_decode_object_key,omitempty"`
	// Optional: alternative to BucketPath
	Bucket string `json:"bucket,omitempty" yaml:"bucket,omitempty"`
}

type fileInfo struct {
	bucket string
	path   string
}

func (c *SQSFilesConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.AccessKey == "" {
		return errors.New("missing access_key")
	}
	if c.SecretKey == "" {
		return errors.New("missing secret_key")
	}
	if c.Region == "" {
		return errors.New("missing region")
	}
	if c.QueueURL == "" {
		return errors.New("missing queue_url")
	}
	return nil
}

func NewSQSFilesAdapter(ctx context.Context, conf SQSFilesConfig) (*SQSFilesAdapter, chan struct{}, error) {
	if conf.ParallelFetch <= 0 {
		conf.ParallelFetch = 1
	}
	if conf.BucketPath == "" {
		conf.BucketPath = "bucket"
	}
	if conf.FilePath == "" {
		conf.FilePath = "files/path"
	}

	a := &SQSFilesAdapter{
		conf:        conf,
		ctx:         context.Background(),
		downloaders: map[string]*s3manager.Downloader{},
	}

	var err error

	a.awsCreds = credentials.NewStaticCredentials(conf.AccessKey, conf.SecretKey, "")

	// SQS
	a.awsConfig = &aws.Config{
		Region:      aws.String(conf.Region),
		Credentials: a.awsCreds,
	}

	if a.awsSession, err = session.NewSession(a.awsConfig); err != nil {
		return nil, nil, err
	}

	a.sqsClient = sqs.New(a.awsSession)

	// The S3 SDKs are initialized at run-time, per bucket, as SQS events
	// name them.

	a.chFiles = make(chan fileInfo)

	a.uspClient, err = uspclient.NewClient(ctx, conf.ClientOptions)
	if err != nil {
		return nil, nil, err
	}

	// Start the processors.
	for i := 0; i < a.conf.ParallelFetch; i++ {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.processFiles()
		}()
	}

	var subErr error
	chStopped := make(chan struct{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer close(chStopped)
		subErr = a.receiveEvents()
	}()
	// Give it a second to start the subscriber to check it's
	// working without any errors.
	time.Sleep(2 * time.Second)
	if subErr != nil {
		a.uspClient.Close()
		return nil, nil, subErr
	}

	return a, chStopped, nil
}

func (a *SQSFilesAdapter) Close() error {
	a.conf.ClientOptions.DebugLog("closing")
	a.isStop = true
	a.wg.Wait()
	if _, err := a.uspClient.Close(); err != nil {
		return err
	}
	return nil
}

// initS3SDKs makes sure a downloader exists for bucket, resolving the
// bucket's region once and caching the result. Without the cache every SQS
// message paid for a fresh GetBucketRegion call and rebuilt the session,
// which is both a per-message round trip and a throttling risk at volume.
func (a *SQSFilesAdapter) initS3SDKs(bucket string) error {
	a.s3Mutex.Lock()
	defer a.s3Mutex.Unlock()

	if _, ok := a.downloaders[bucket]; ok {
		return nil
	}

	region, err := a.getBucketRegion(bucket)
	if err != nil {
		return fmt.Errorf("s3.Region: %v", err)
	}

	// The downloader must use the bucket's region, not the region the SQS
	// queue happens to live in.
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: a.awsCreds,
	})
	if err != nil {
		return fmt.Errorf("s3.NewSession(): %v", err)
	}

	a.downloaders[bucket] = s3manager.NewDownloader(sess)
	return nil
}

// getDownloader returns the cached downloader for bucket. receiveEvents
// always calls initS3SDKs before queueing a file, so a miss means the file
// was queued without initialization.
func (a *SQSFilesAdapter) getDownloader(bucket string) (*s3manager.Downloader, error) {
	a.s3Mutex.Lock()
	defer a.s3Mutex.Unlock()

	d, ok := a.downloaders[bucket]
	if !ok {
		return nil, fmt.Errorf("no S3 downloader for bucket %s", bucket)
	}
	return d, nil
}

// getBucketRegion resolves which region a bucket lives in so the downloader
// talks to the right endpoint.
//
// It must sign with the adapter's own credentials. An empty aws.Config falls
// through to the SDK's default chain -- environment, shared config, instance
// profile, web identity -- so on a host whose ambient AWS config points at a
// role, this lookup attempts an STS AssumeRole and fails with "unable to
// assume role", even though the adapter's own credentials can read the bucket
// perfectly well.
//
// A lookup failure is not fatal. The configured region is a reasonable
// fallback and keeps the adapter running when the credentials are not allowed
// s3:GetBucketLocation. If that fallback is wrong, the per-file download fails
// with a clear S3 error instead of the adapter refusing to start.
func (a *SQSFilesAdapter) getBucketRegion(bucket string) (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(a.conf.Region),
		Credentials: a.awsCreds,
	})
	if err != nil {
		return "", fmt.Errorf("s3.NewSession(): %v", err)
	}

	region, err := s3manager.GetBucketRegion(a.ctx, sess, bucket, a.conf.Region)
	if err != nil {
		a.conf.ClientOptions.OnWarning(fmt.Sprintf("s3.GetBucketRegion(%s): %v, falling back to configured region %s", bucket, err, a.conf.Region))
		return a.conf.Region, nil
	}
	return region, nil
}

func (a *SQSFilesAdapter) receiveEvents() error {
	defer close(a.chFiles)

	for !a.isStop {
		result, err := a.sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
			AttributeNames:        []*string{},
			MessageAttributeNames: []*string{},
			QueueUrl:              &a.conf.QueueURL,
			MaxNumberOfMessages:   aws.Int64(10),
			VisibilityTimeout:     aws.Int64(60), // 60 seconds
			WaitTimeSeconds:       aws.Int64(5),
		})
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("sqsClient.ReceiveMessage: %v", err))
			return err
		}
		delRequest := &sqs.DeleteMessageBatchInput{
			Entries:  make([]*sqs.DeleteMessageBatchRequestEntry, 0, len(result.Messages)),
			QueueUrl: &a.conf.QueueURL,
		}
		if len(result.Messages) == 0 {
			continue
		}
		for _, msg := range result.Messages {
			delRequest.Entries = append(delRequest.Entries, &sqs.DeleteMessageBatchRequestEntry{
				Id:            msg.MessageId,
				ReceiptHandle: msg.ReceiptHandle,
			})

			d := utils.Dict{}
			if err := json.Unmarshal([]byte(*msg.Body), &d); err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("sqsClient.Message.Json: %v", err))
				continue
			}

			bucket := a.conf.Bucket
			if bucket == "" {
				bucket = d.ExpandableFindOneString(a.conf.BucketPath)
			}
			filePaths := d.ExpandableFindString(a.conf.FilePath)

			if bucket == "" {
				a.conf.ClientOptions.OnError(errors.New("sqsClient.Message: missing bucket"))
				continue
			}
			if len(filePaths) == 0 {
				continue
			}
			if err := a.initS3SDKs(bucket); err != nil {
				a.conf.ClientOptions.OnError(err)
				return err
			}

			for _, p := range filePaths {
				a.chFiles <- fileInfo{
					bucket: bucket,
					path:   p,
				}
			}

		}
		delRes, err := a.sqsClient.DeleteMessageBatch(delRequest)
		if err != nil {
			return err
		}
		if len(delRes.Failed) != 0 {
			return errors.New("sqsClient.DeleteMessageBatch: failed to delete some messages")
		}
	}
	return nil
}

func (a *SQSFilesAdapter) processFiles() error {
	for f := range a.chFiles {
		path := f.path
		if a.conf.IsDecodeObjectKey {
			// URL Decode the path
			var err error
			path, err = url.QueryUnescape(path)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("url.QueryUnescape(): %v", err))
				continue
			}
		}
		downloader, err := a.getDownloader(f.bucket)
		if err != nil {
			a.conf.ClientOptions.OnError(err)
			continue
		}

		startTime := time.Now().UTC()
		a.conf.ClientOptions.DebugLog(fmt.Sprintf("downloading file %s", path))

		writerAt := aws.NewWriteAtBuffer([]byte{})

		if _, err := downloader.Download(writerAt, &s3.GetObjectInput{
			Bucket: aws.String(f.bucket),
			Key:    aws.String(path),
		}); err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("s3.Download(): %v", err))
			return err
		}
		// PrepareBundleData routes through the parquet decoder when
		// needed (including gzipped parquet) and otherwise returns the
		// bytes untouched.
		rawData, isCompressed, err := utils.PrepareBundleData(path, writerAt.Bytes())
		if err != nil {
			a.conf.ClientOptions.OnError(err)
			continue
		}

		a.conf.ClientOptions.DebugLog(fmt.Sprintf("file %s downloaded in %v", path, time.Since(startTime)))

		a.processEvent(rawData, isCompressed)
	}
	return nil
}

func (a *SQSFilesAdapter) processEvent(data []byte, isCompressed bool) bool {
	// Since we're dealing with files, we use the
	// bundle payloads to avoid having to go through
	// the whole unmarshal+marshal roundtrip.
	var msg *protocol.DataMessage
	if isCompressed {
		msg = &protocol.DataMessage{
			CompressedBundlePayload: data,
			TimestampMs:             uint64(time.Now().UnixNano() / int64(time.Millisecond)),
		}
	} else {
		msg = &protocol.DataMessage{
			BundlePayload: data,
			TimestampMs:   uint64(time.Now().UnixNano() / int64(time.Millisecond)),
		}
	}

	if err := a.uspClient.Ship(msg, 10*time.Second); err != nil {
		if err == uspclient.ErrorBufferFull {
			a.conf.ClientOptions.OnWarning("stream falling behind")
			err = a.uspClient.Ship(msg, 1*time.Hour)
		}
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("Ship(): %v", err))
			return false
		}
	}
	return true
}
