use anyhow::Result;
use std::{fs::OpenOptions, io::Write, path::Path};

pub fn save_to_file<P: AsRef<Path>>(data: &[u8], file_path: P) -> Result<()> {
    // Save the data to a file at the specified file path
    // Returns an error if the save operation fails
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(file_path.as_ref())?;
    file.write_all(data)?;

    Ok(())
}

pub fn load_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    // Load data from a file at the specified file path
    // Returns the loaded data or an error if the load operation fails
    let data = std::fs::read(file_path)?;
    Ok(data)
}

// write test
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_save_to_file() {
        let data = b"test data";
        let file_path = "./test_file.txt";

        let result = save_to_file(data, file_path);
        assert!(result.is_ok(), "Failed to save to file: {:?}", result.err());

        // Assert that the file exists
        assert!(
            Path::new(file_path).exists(),
            "File does not exist after save_to_file"
        );

        let loaded_data = fs::read(file_path).unwrap();
        assert_eq!(data, loaded_data.as_slice());

        fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_load_from_file() {
        let data = b"test data";
        let file_path = "./test_file2.txt";

        fs::write(file_path, data).unwrap();

        let loaded_data = load_from_file(file_path).unwrap();
        assert_eq!(data, loaded_data.as_slice());

        fs::remove_file(file_path).unwrap();
    }
}
