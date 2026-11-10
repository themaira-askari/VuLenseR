
from services.analysis_service import analyze_requirement

requirement = """
The user should be able to log in to the system.
"""

result = analyze_requirement(requirement)

print(result)
