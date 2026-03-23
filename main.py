import argparse
import sys
import os

from parser import parse_eml
from ioc import extract_iocs
from analyzer import calculate_risk_score
from report import generate_report, report_to_markdown, report_to_json


def process_email(file_path, output_format="markdown", output_file=None):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        return None

    try:
        parsed_email = parse_eml(file_path)
        iocs = extract_iocs(parsed_email)
        analysis_results = calculate_risk_score(parsed_email, iocs)
        report_data = generate_report(parsed_email, iocs, analysis_results)

        if output_format == "json":
            content = report_to_json(report_data)
        else:
            content = report_to_markdown(report_data)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Report saved to {output_file}")
        else:
            print(content)

        return report_data

    except Exception as e:
        print(f"Error processing '{file_path}': {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return None


def collect_files(inputs):
    files = []
    for input_path in inputs:
        if os.path.isdir(input_path):
            for filename in os.listdir(input_path):
                if filename.lower().endswith(".eml"):
                    files.append(os.path.join(input_path, filename))
        elif os.path.isfile(input_path):
            files.append(input_path)
        else:
            print(
                f"Warning: '{input_path}' is not a valid file or directory, skipping.",
                file=sys.stderr,
            )
    return files


def main():
    parser = argparse.ArgumentParser(description="Phishing Triage Workflow")
    parser.add_argument(
        "files", nargs="+", help="Path(s) to .eml file(s) or directory(ies) to analyze"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument(
        "-s",
        "--summary",
        action="store_true",
        help="Show summary table for multiple files",
    )

    args = parser.parse_args()

    all_files = collect_files(args.files)

    if not all_files:
        print("Error: No valid .eml files found.", file=sys.stderr)
        sys.exit(1)

    if args.output and len(all_files) > 1:
        base_name = os.path.splitext(args.output)[0]
        ext = os.path.splitext(args.output)[1] or (
            ".json" if args.format == "json" else ".md"
        )
        for file_path in all_files:
            file_name = os.path.splitext(os.path.basename(file_path))[0]
            out_file = f"{base_name}_{file_name}{ext}"
            process_email(file_path, args.format, out_file)
    else:
        for file_path in all_files:
            print(f"\n{'=' * 60}")
            print(f"Analyzing: {file_path}")
            print("=" * 60)
            process_email(
                file_path, args.format, args.output if len(all_files) == 1 else None
            )

    if args.summary and len(all_files) > 1:
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"{'File':<40} {'Score':>6}")
        print("-" * 60)
        for file_path in all_files:
            if not os.path.exists(file_path):
                continue
            try:
                parsed_email = parse_eml(file_path)
                iocs = extract_iocs(parsed_email)
                analysis_results = calculate_risk_score(parsed_email, iocs)
                score = analysis_results["total_score"]
                risk = "HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW")
                print(f"{os.path.basename(file_path):<40} {score:>4} {risk}")
            except Exception:
                print(f"{os.path.basename(file_path):<40} {'ERR':>6}")


if __name__ == "__main__":
    main()
