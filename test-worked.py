import subprocess
import json
import os
import requests
from dotenv import load_dotenv

# ---------------------------
# КОНФИГУРАЦИЯ
# ---------------------------

load_dotenv()

DD_API_URL = os.getenv("DD_API_URL")
DD_API_KEY = os.getenv("DD_API_KEY")
DD_ENGAGEMENT_ID = os.getenv("DD_ENGAGEMENT_ID")

# Импорт уязвимостей, связанные с шифрованием
KEYWORDS = [
    "crypto",
    "encryption",
    "ssl",
    "tls",
    "cipher",
    "aes",
    "rsa", 
    "des",
    "md5",
    "sha",
    "signature",
    "private key",
    "certificate",
    "x509",
]

repos = [
    "https://github.com/PandaTBE/mixaluch-front",
    "https://github.com/zaivanza/aio-cex",
    "https://github.com/zaivanza/all-in-one-v2",
    "https://github.com/mxnster/infernet-container-starter",
    "https://github.com/mxnster/gate-Wallets-withdraw",
    "https://github.com/nazavod777/usual_checker",
    "https://github.com/nazavod777/wallets_checker",
]

# ---------------------------
# Шаг 1: Сканирование Trivy
# ---------------------------

def run_trivy_scan(repo_url):
    command = [
        "trivy", "repo", repo_url,
        "--format", "json",
        "--output", "report.json"
    ]
    subprocess.run(command, check=True)  # При ошибке сканирования будет исключение
    return "report.json"

# ---------------------------
# Шаг 2: Фильтрация по ключевым словам
# ---------------------------

def filter_by_keyword(report, keywords):
    """
    Возвращает:
      - report (отфильтрованный),
      - count_kept (сколько уязвимостей оставили),
      - count_removed (сколько уязвимостей исключили),
      - matched_vulns_info (список словарей, чтобы печатать: 
        [{title: ..., matched_keywords: [...]}, ...])
    """
    count_kept = 0
    count_removed = 0
    matched_vulns_info = []

    results = report.get("Results", [])

    for r in results:
        vulns = r.get("Vulnerabilities", [])
        new_vulns = []

        for v in vulns:
            title = v.get("Title", "").lower()
            description = v.get("Description", "").lower()
            
            # Проверка, какие именно ключевые слова встретились
            matched_keywords = []
            for k in keywords:
                if k in title or k == description:
                    matched_keywords.append(k)

            if len(matched_keywords) > 0:
                # Если нашлись совпадения, оставляем уязвимость
                count_kept += 1
                new_vulns.append(v)
                matched_vulns_info.append({
                    "title": v.get("Title", ""),
                    "matched_keywords": matched_keywords
                })
            else:
                count_removed += 1
        
        r["Vulnerabilities"] = new_vulns

    return report, count_kept, count_removed, matched_vulns_info


def apply_filter(input_file, output_file, keywords):
    """
    1. Загружается JSON-отчёт из input_file.
    2. Вызывается filter_by_keyword(...) для фильтрации уязвимостей.
    3. Сохраняется отфильтрованный отчёт в output_file.
    4. Возвращается (output_file, count_kept, count_removed, matched_vulns_info).
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        f.close()

    filtered_data, kept, removed, matched_info = filter_by_keyword(data, keywords)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, ensure_ascii=False, indent=2)
        f.close()

    return output_file, kept, removed, matched_info

# ---------------------------
# Шаг 3: Загрузка в DefectDojo
# ---------------------------

def upload_to_defectdojo(api_url, api_key, engagement_id, json_file_path):
    headers = {
        'Authorization': f'Token {api_key}'
    }
    data = {
        'scan_type': 'Trivy Scan',
        'engagement': engagement_id,
        'active': 'true',
        'verified': 'false',
        'close_old_findings': 'false',
        'skip_duplicates': 'true'
    }
    with open(json_file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(
            f"{api_url}/api/v2/import-scan/",
            headers=headers, data=data, files=files
        )
    
    if response.status_code == 201:
        print(f"Import successful for {json_file_path}!")
    else:
        print(f"Error importing scan: {response.status_code} - {response.text}")

# ---------------------------
# Основная логика
# ---------------------------

def main():
    for repo in repos:
        print(f"Scanning {repo} with Trivy...")
        json_report_path = run_trivy_scan(repo)

        # Фильтр уязвимостей, остаются только те, где есть ключевые слова
        filtered_path = "report_filtered.json"
        filtered_file, kept_count, removed_count, matched_vulns_info = apply_filter(
            json_report_path, 
            filtered_path, 
            KEYWORDS
        )

        # Вывод статистики
        print(f"\n=== {repo} ===")
        print(f"  Kept    : {kept_count} (уязвимостей осталось, т.к. совпали ключевые слова)")
        print(f"  Removed : {removed_count} (уязвимостей исключено)")
        
        # Отображение какие именно ключи совпали для каждой уязвимости:
        if matched_vulns_info:
            print("  Matched vulnerabilities:")
            for item in matched_vulns_info:
                print(f"    - Title: {item['title']}")
                print(f"      Keywords matched: {', '.join(item['matched_keywords'])}")
        else:
            print("  No matching vulnerabilities found for specified keywords.")

        print(f"\nUploading {filtered_path} for {repo} to DefectDojo...")
        upload_to_defectdojo(DD_API_URL, DD_API_KEY, DD_ENGAGEMENT_ID, filtered_path)
        print("="*50, "\n")

if __name__ == "__main__":
    main()