
from services.security_analysis_service import (
    analyze_security_requirement
)


# Sample software requirement
requirement = """
The user should be able to log in to the system.
"""


# Security analysis run karna
print("\n--- Security Requirements Analysis ---\n")

result = analyze_security_requirement(requirement)


# Result display karna
print(result)


print("\n--- Security Analysis Test Completed ---")
