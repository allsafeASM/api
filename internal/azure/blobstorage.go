package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/allsafeASM/api/internal/models"
	"github.com/google/uuid"
	"github.com/projectdiscovery/gologger"
)

// BlobStorageClient wraps Azure Blob Storage operations
type BlobStorageClient struct {
	client        *azblob.Client
	containerName string
}

// NewBlobStorageClient creates a new Blob Storage client
func NewBlobStorageClient(connectionString, containerName string) (*BlobStorageClient, error) {
	client, err := azblob.NewClientFromConnectionString(connectionString, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob storage client: %w", err)
	}

	return &BlobStorageClient{
		client:        client,
		containerName: containerName,
	}, nil
}

// StoreTaskResult stores a task result in blob storage
func (b *BlobStorageClient) StoreTaskResult(ctx context.Context, result *models.TaskResult) error {
	// Create a unique blob name using timestamp and task ID
	randomID := uuid.New().String()
	blobName := fmt.Sprintf("%s-%d/%s/out/%s.json", result.Domain, result.ScanID, result.Task, randomID)

	// Clean the blob path
	cleanPath := b.cleanBlobPath(blobName)

	// Convert result to JSON
	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal task result: %w", err)
	}

	// Upload to blob storage
	_, err = b.client.UploadBuffer(ctx, b.containerName, cleanPath, jsonData, &azblob.UploadBufferOptions{})
	if err != nil {
		return fmt.Errorf("failed to upload task result to blob storage: %w", err)
	}

	gologger.Debug().Msgf("Stored task result in blob: %s/%s", b.containerName, blobName)
	return nil
}

// cleanBlobPath removes the container name from the path if it's already included
func (b *BlobStorageClient) cleanBlobPath(blobPath string) string {
	// If the path starts with the container name, remove it
	if strings.HasPrefix(blobPath, b.containerName+"/") {
		return strings.TrimPrefix(blobPath, b.containerName+"/")
	}
	return blobPath
}

// ReadFileFromBlob reads a file from blob storage
func (b *BlobStorageClient) ReadFileFromBlob(ctx context.Context, blobPath string) ([]byte, error) {
	// Clean the blob path
	cleanPath := b.cleanBlobPath(blobPath)

	// Download from blob storage
	response, err := b.client.DownloadStream(ctx, b.containerName, cleanPath, &azblob.DownloadStreamOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to download file from blob storage: %w", err)
	}
	defer response.Body.Close()

	// Read the content
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob content %s: %w", cleanPath, err)
	}

	gologger.Debug().Msgf("Read file from blob: %s/%s (%d bytes)", b.containerName, cleanPath, len(content))
	return content, nil
}

// ReadHostsFileFromBlob reads a hosts file from blob storage and returns the content as string
func (b *BlobStorageClient) ReadHostsFileFromBlob(ctx context.Context, blobPath string) (string, error) {
	// Clean the blob path to prevent double container names
	cleanPath := b.cleanBlobPath(blobPath)

	content, err := b.ReadFileFromBlob(ctx, cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to read hosts file from blob %s: %w", cleanPath, err)
	}

	return string(content), nil
}

// StoreSubfinderTextResult stores a plain text file of subfinder subdomains in blob storage
func (b *BlobStorageClient) StoreSubfinderTextResult(ctx context.Context, result *models.SubfinderResult, scanID int, task string) error {
	randomID := uuid.New().String()
	blobName := fmt.Sprintf("%s-%d/%s/out/%s.txt", result.Domain, scanID, task, randomID)
	txtContent := strings.Join(result.Subdomains, "\n")

	_, err := b.client.UploadBuffer(ctx, b.containerName, blobName, []byte(txtContent), &azblob.UploadBufferOptions{})
	if err != nil {
		return fmt.Errorf("failed to upload subfinder text result to blob storage: %w", err)
	}

	gologger.Debug().Msgf("Stored subfinder txt result in blob: %s/%s", b.containerName, blobName)
	return nil
}

// DownloadFile downloads a blob from Azure Blob Storage and saves it to a local file path
func (b *BlobStorageClient) DownloadFile(ctx context.Context, blobPath string, localPath string) error {
	cleanPath := b.cleanBlobPath(blobPath)
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file %s: %w", localPath, err)
	}
	defer file.Close()

	response, err := b.client.DownloadStream(ctx, b.containerName, cleanPath, &azblob.DownloadStreamOptions{})
	if err != nil {
		return fmt.Errorf("failed to download blob %s: %w", cleanPath, err)
	}
	defer response.Body.Close()

	_, err = io.Copy(file, response.Body)
	if err != nil {
		return fmt.Errorf("failed to write blob content to file %s: %w", localPath, err)
	}

	gologger.Debug().Msgf("Downloaded blob %s/%s to local file %s", b.containerName, cleanPath, localPath)
	return nil
}

// DeleteLocalFile deletes a local file at the given path
func (b *BlobStorageClient) DeleteLocalFile(localPath string) error {
	err := os.Remove(localPath)
	if err != nil {
		gologger.Warning().Msgf("Failed to delete local file: %s, error: %v", localPath, err)
		return err
	}
	gologger.Info().Msgf("Deleted local file: %s", localPath)
	return nil
}
