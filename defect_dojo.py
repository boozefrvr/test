import subprocess
import requests
import logging
import json
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DefectDojo:
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

    REPOS = [
        "https://github.com/PandaTBE/mixaluch-front",
        "https://github.com/zaivanza/aio-cex",
        "https://github.com/zaivanza/all-in-one-v2",
        "https://github.com/mxnster/infernet-container-starter",
        "https://github.com/mxnster/gate-Wallets-withdraw",
        "https://github.com/nazavod777/usual_checker",
        "https://github.com/nazavod777/wallets_checker",
    ]

    def __init__(
        self,
        dd_api_url: str,
        dd_api_key: str,
        dd_engagement_id: str,
    ):
        self.dd_api_url = dd_api_url
        self.dd_api_key = dd_api_key
        self.dd_engagement_id = dd_engagement_id

    def run_trivy_scan(self, repo_url):
        file_name = self.get_repo_name(repo_url)
        command = [
            "trivy",
            "repo",
            repo_url,
            "--format",
            "json",
            "--output",
            file_name,
        ]
        subprocess.run(command, check=True)  # При ошибке сканирования будет исключение
        return file_name
    
    def get_repo_name(self, line: str) -> str:
        # 2. Парсим URL
        parsed_url = urlparse(line)
        # Пример: parsed_url.path может выглядеть как "/PandaTBE/mixaluch-front.json"

        # 3. Извлекаем последний сегмент пути
        path_parts = parsed_url.path.strip('/').split('/')
        last_part = path_parts[-1] if path_parts else ''

        # 4. Убираем '.json' в конце, если есть
        if last_part.endswith('.json'):
            last_part = last_part[:-5]  # убираем 5 символов (".json")

        return f"report_{last_part}"
    
    def filter_by_keyword(self, report, keywords):
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
                    matched_vulns_info.append(
                        {
                            "title": v.get("Title", ""),
                            "matched_keywords": matched_keywords,
                        }
                    )
                else:
                    count_removed += 1

            r["Vulnerabilities"] = new_vulns

        return report, count_kept, count_removed, matched_vulns_info

    def apply_filter(self, input_file, output_file):
        """
        1. Загружается JSON-отчёт из input_file.
        2. Вызывается filter_by_keyword(...) для фильтрации уязвимостей.
        3. Сохраняется отфильтрованный отчёт в output_file.
        4. Возвращается (output_file, count_kept, count_removed, matched_vulns_info).
        """
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            f.close()

        filtered_data, kept, removed, matched_info = self.filter_by_keyword(
            data, self.KEYWORDS
        )

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=2)
            f.close()

        return kept, removed, matched_info

    def print_statistics(
        self, repo_name, kept_count, removed_count, matched_vulns_info
    ):
        """
        вывод статистики
        Args:
            repo_name (str): Название репозитория
            kept_count (int): Сколько уязвимостей оставили
            removed_count (int): Сколько уязвимостей исключили
            matched_vulns_info (arr): Список словарей
        """
        print(f"\n=== {repo_name} ===")
        print(
            f"  Kept    : {kept_count} (уязвимостей осталось, т.к. совпали ключевые слова)"
        )
        print(f"  Removed : {removed_count} (уязвимостей исключено)")

        # Отображение какие именно ключи совпали для каждой уязвимости:
        if matched_vulns_info:
            print("Совпавшие уязвимости:")
            for item in matched_vulns_info:
                print(f"    - Название: {item['title']}")
                print(
                    f"    - Найденные ключевые слова: {', '.join(item['matched_keywords'])}"
                )
        else:
            print("Уязвимости, соответствующие указанным ключевым словам, не найдены.")

    def upload_to_defect_dojo(self, filtered_file_name):
        headers = {"Authorization": f"Token {self.dd_api_key}"}
        data = {
            "scan_type": "Trivy Scan",
            "engagement": self.dd_engagement_id,
            "active": "true",
            "verified": "false",
            "close_old_findings": "false",
            "skip_duplicates": "true",
        }
        with open(filtered_file_name, "rb") as f:
            files = {"file": f}
            response = requests.post(
                f"{self.dd_api_url}/api/v2/import-scan/",
                headers=headers,
                data=data,
                files=files,
            )

        if response.status_code == 201:
            print(f"Данные успешно загружены {filtered_file_name}!")
        else:
            print(
                f"При загрузке файла возникла ошибка: {response.status_code} - {response.text}"
            )

    def start(self):
        for repo in self.REPOS:
            logger.info(f"Сканирование репозитория {repo}...")
            report_name = self.run_trivy_scan(repo)
            filtered_file_name = f"report_filtered_{report_name}"
            kept_count, removed_count, matched_vulns_info = self.apply_filter(
                report_name, filtered_file_name
            )
            self.print_statistics(repo, kept_count, removed_count, matched_vulns_info)
            logger.info(
                f"Загрузка файла {filtered_file_name} для репозитория {repo} в DefectDojo..."
            )
            self.upload_to_defect_dojo(filtered_file_name)
