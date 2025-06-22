package utils

import (
  "log"
  "os"
  "fmt"
  "encoding/json"
  "api/config"
  "api/internal/models"
)

// FailOnError logs the error and exits the program if the error is not nil.
func FailOnError(err error, msg string) {
  if err != nil {
    log.Fatalf("%s: %s", msg, err)
  }
}

// SaveToFile saves the given data to the specified file.
func SaveToFile(res models.ScanResponse) error {
  // Create results directory if not exists
  err := os.MkdirAll(config.ResultsStorageDir, os.ModePerm)
  if err != nil {
    return err
  }

  // Generate filename
  filename := fmt.Sprintf("%s/%v.json", config.ResultsStorageDir, res.ScanID)

  // Serialize the data to JSON
  json, err := json.Marshal(res)
  if err != nil {
    return err
  }

  // Write the JSON data to the file
	err = os.WriteFile(filename, json, 0644)
  if err != nil {
    return err
  }

  return nil
}

