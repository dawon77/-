import json
import re
import sys

# 설정 파일 불러오기
def load_settings(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"오류: 설정 파일 '{filename}'이(가) 없습니다. 프로그램을 종료합니다.")
        sys.exit(1)  # 파일이 없으면 프로그램 종료

# 사용자 보안 평가 클래스
class SecurityEvaluator:
    def __init__(self, name, email, password, tracking_permission, settings):
        self.name = name
        self.email = email
        self.password = password
        self.tracking_permission = tracking_permission
        self.settings = settings
        self.result = {
            "email_valid": False,
            "password_issues": [],
            "tracking_warning": ""
        }

    def analyze(self):
        self._validate_email()
        self._check_password_strength()
        self._evaluate_tracking()
        return self.result

    def _validate_email(self):
        self.result["email_valid"] = bool(re.match(r"[^@]+@[^@]+\.[^@]+", self.email))

    def _check_password_strength(self):
        pw = self.password
        policy = self.settings["password_policy"]

        if len(pw) < self.settings["min_password_length"]:
            self.result["password_issues"].append(policy["penalty_for_short"])

        if self.settings["require_uppercase"] and not re.search(r"[A-Z]", pw):
            self.result["password_issues"].append(policy["penalty_for_no_upper"])

        if self.settings["require_numbers"] and not re.search(r"\d", pw):
            self.result["password_issues"].append(policy["penalty_for_no_number"])

        if self.settings["require_special_char"] and not re.search(r"[\W_]", pw):
            self.result["password_issues"].append(policy["penalty_for_no_special"])

    def _evaluate_tracking(self):
        if self.settings["evaluate_tracking"] and self.tracking_permission.lower() == 'y':
            self.result["tracking_warning"] = "개인정보 추적을 허용했습니다. 주의가 필요합니다."

# 메인 실행 부분
if __name__ == "__main__":
    settings = load_settings("security_settings.json")

    name = input("이름을 입력하세요: ")
    email = input("이메일을 입력하세요: ")
    password = input("비밀번호를 입력하세요: ")
    tracking = input("웹사이트 추적 허용? (y/n): ")

    user = SecurityEvaluator(name, email, password, tracking, settings)
    result = user.analyze()

    print("\n분석 결과:")
    print("이메일 유효성:", "정상" if result["email_valid"] else "유효하지 않음")
    print("비밀번호 문제점:")
    if result["password_issues"]:
        for issue in result["password_issues"]:
            print("-", issue)
    else:
        print("- 비밀번호는 안전합니다.")
    print("추적 허용 경고:", result["tracking_warning"] or "없음")
