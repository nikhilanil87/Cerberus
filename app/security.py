import re

class SovereignScrubber:
    def __init__(self):
        # Patterns for Email, Phone Numbers, and generic API Keys
        self.patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "secret": r'(ghp_|sk-)[a-zA-Z0-9]{36,}' # GitHub/OpenAI style keys
        }

    def scrub(self, text: str) -> str:
        if not isinstance(text, str):
            return text
            
        scrubbed_text = text
        for label, pattern in self.patterns.items():
            count = len(re.findall(pattern, scrubbed_text))
            if count > 0:
                scrubbed_text = re.sub(pattern, f"[REDACTED_{label.upper()}]", scrubbed_text)
                print(f"PRIVACY: Redacted {count} {label}(s) from data stream.")
        
        return scrubbed_text

# Initialize a global instance
scrubber = SovereignScrubber()