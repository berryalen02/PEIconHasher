package main

import (
	"crypto/md5"
	"debug/pe"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"
)

// AddNoiseToBytes adds random noise to a byte slice
func AddNoiseToBytes(data []byte) []byte {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 10; i++ { // Increase the number of noise points
		index := rand.Intn(len(data))
		data[index] = byte(rand.Intn(256))
	}
	return data
}

// CalculateHash calculates the MD5 hash of the byte slice
func CalculateHash(data []byte) string {
	hash := md5.New()
	hash.Write(data)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func main() {
	fmt.Println("______ _____ _____                _   _           _               \n| ___ \\  ___|_   _|              | | | |         | |              \n| |_/ / |__   | |  ___ ___  _ __ | |_| | __ _ ___| |__   ___ _ __ \n|  __/|  __|  | | / __/ _ \\| '_ \\|  _  |/ _` / __| '_ \\ / _ \\ '__|\n| |   | |___ _| || (_| (_) | | | | | | | (_| \\__ \\ | | |  __/ |   \n\\_|   \\____/ \\___/\\___\\___/|_| |_\\_| |_/\\__,_|___/_| |_|\\___|_|   \n                                                                  \n                                                                  ")
	fmt.Println("Link: https://github.com/berryalen02/PEIconHasher")

	peFilePath := flag.String("f", "", "需要更改ico hash的PE文件")
	flag.Parse()

	if *peFilePath == "" {
		fmt.Println("Usage: -f <path_to_pe_file>")
		return
	}

	// Open the PE file
	file, err := os.OpenFile(*peFilePath, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening PE file:", err)
		return
	}
	defer file.Close()

	// Parse the PE file
	peFile, err := pe.NewFile(file)
	if err != nil {
		fmt.Println("Error parsing PE file:", err)
		return
	}

	// Locate the icon resource section
	var iconSection *pe.Section
	for _, section := range peFile.Sections {
		if section.Name == ".rsrc" {
			iconSection = section
			break
		}
	}

	if iconSection == nil {
		fmt.Println("Icon resource section not found")
		return
	}

	// Read the icon data
	iconData, err := iconSection.Data()
	if err != nil {
		fmt.Println("Error reading icon data:", err)
		return
	}

	originalHash := CalculateHash(iconData)

	// Add noise to the icon data
	noisyIconData := AddNoiseToBytes(iconData)

	// Calculate and print the hash of the original and noisy icon data
	noisyHash := CalculateHash(noisyIconData)
	fmt.Println("Original Icon Hash:", originalHash)
	fmt.Println("Noisy Icon Hash:", noisyHash)

	// Write the noisy icon data back to the PE file
	_, err = file.WriteAt(noisyIconData, int64(iconSection.Offset))
	if err != nil {
		fmt.Println("Error writing noisy icon data to PE file:", err)
		return
	}

	fmt.Println("Icon hash modified successfully")
}
