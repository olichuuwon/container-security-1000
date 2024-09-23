import os
import json

# Define the directory containing the scan result files
directory_path = os.path.join(os.getcwd(), "results")  # Replace with your folder path


# Define the directory where the filtered results will be saved
filtered_results_directory = os.path.join(directory_path, "filtered_results")

# Create the 'filtered_results' directory if it doesn't exist
if not os.path.exists(filtered_results_directory):
    os.makedirs(filtered_results_directory)


# Define the severity levels to filter
desired_severities = ["HIGH", "CRITICAL"]

# Loop through each file in the directory
for filename in os.listdir(directory_path):
    if filename.endswith(".json"):  # Process only JSON files
        file_path = os.path.join(directory_path, filename)
        print(f"Processing file: {file_path}")

        # Load and parse the JSON data from the current file with explicit encoding
        try:
            with open(
                file_path, "r", encoding="utf-8"
            ) as file:  # Specify UTF-8 encoding
                data = json.load(file)
        except UnicodeDecodeError as e:
            print(f"Error reading {file_path}: {e}")
            continue  # Skip this file and move to the next

        # Check if data is a list (e.g., a list of results)
        if isinstance(data, list):
            results = data
        elif isinstance(data, dict):
            results = data.get("Results", [])
        else:
            print(f"Unexpected data format in {file_path}")
            continue  # Skip this file if the format is unknown

        # Initialize a list to store the filtered vulnerabilities for the current file
        filtered_vulnerabilities = []

        # Loop through the vulnerabilities and filter based on severity
        for result in results:
            if "Vulnerabilities" in result:
                for vuln in result["Vulnerabilities"]:
                    severity = vuln.get("Severity", "").upper()
                    if severity in desired_severities:
                        filtered_vulnerabilities.append(
                            {
                                "VulnerabilityID": vuln.get("VulnerabilityID"),
                                "PkgName": vuln.get("PkgName"),
                                "InstalledVersion": vuln.get("InstalledVersion"),
                                "Severity": severity,
                                "Description": vuln.get("Description"),
                                "PrimaryURL": vuln.get("PrimaryURL"),
                            }
                        )

        # Define the output file path in the 'filtered_results' directory
        output_file_path = os.path.join(
            filtered_results_directory, f"filtered_{filename}"
        )

        # Save the filtered results to a new JSON file
        with open(output_file_path, "w", encoding="utf-8") as output_file:
            json.dump(filtered_vulnerabilities, output_file, indent=4)

        print(f"Filtered vulnerabilities saved to: {output_file_path}")
