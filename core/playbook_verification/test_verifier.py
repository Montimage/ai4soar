import os
import json
import sys
import requests
from verifier import PlaybookVerifier, simplify_shuffle_playbook
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def test_shuffle_playbook_verification(playbook_path):
    """Test verification of a Shuffle playbook using OpenAI after simplification."""
    # Load the Shuffle playbook JSON
    with open(playbook_path, "r") as f:
        shuffle_json = json.load(f)

    # Simplify the playbook
    simplified = simplify_shuffle_playbook(shuffle_json)
    print(f"\nSimplified Playbook from {playbook_path}:")
    print(json.dumps(simplified, indent=2))

    # Write simplified playbook to file
    if playbook_path.lower().endswith('.json'):
        output_path = playbook_path[:-5] + '_simplified.json'
    else:
        output_path = playbook_path + '_simplified.json'
    with open(output_path, 'w') as out_f:
        json.dump(simplified, out_f, indent=2)
    print(f"\nSimplified playbook written to {output_path}")

    # Verify using OpenAI
    verifier = PlaybookVerifier(use_local_model=False)
    result = verifier.verify_playbook(simplified)
    print("\nOpenAI Verification Result for Simplified Playbook:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    # Check if API key is available in environment
    if not os.getenv("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY not found in environment variables or .env file")
        print("Please ensure you have a .env file with OPENAI_API_KEY=your-key-here")
        exit(1)

    # Get playbook path from command-line argument, default to 'playbook.json'
    playbook_path = sys.argv[1] if len(sys.argv) > 1 else "playbook.json"

    print(f"Testing Playbook Verification Module with {playbook_path}...")

    # Test Shuffle playbook verification
    test_shuffle_playbook_verification(playbook_path)
