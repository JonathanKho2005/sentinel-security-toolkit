import csv
import json
from pathlib import Path

def validate_results(results):
    # Ensure results is a list of dictionaries
    if not isinstance(results, list):
        raise ValueError("Results must be a list.")

    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Each result must be a dictionary.")

def save_json(results, output_path):
    # Save scan results to a JSON file
    validate_results(results)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        file.write("\n")

    return path

def save_csv(results, output_path):
    # Save scan results to a CSV file

    validate_results(results)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Combine the fields returned by different scan types.
    fieldnames = list(dict.fromkeys(
        key
        for result in results
        for key in result
    ))

    with path.open("w", newline="", encoding="utf-8") as file:
        if not fieldnames:
            return path

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for result in results:
            row = {}

            for key in fieldnames:
                value = result.get(key)

                # Convert nested values into readable CSV text
                if isinstance(value, (dict, list, tuple)):
                    value = json.dumps(value, default=str)
                elif value is None:
                    value = ""

                row[key] = value

            writer.writerow(row)

    return path


def save_report(results, output_path):
    """Save a report based on the file extension."""

    path = Path(output_path)
    extension = path.suffix.lower()

    if extension == ".json":
        return save_json(results, path)

    if extension == ".csv":
        return save_csv(results, path)

    raise ValueError(
        "Unsupported report format. Use .json or .csv."
    )