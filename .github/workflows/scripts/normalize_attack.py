import re

ATTACK_TYPE_MAPPING = {
    # Access Control
    r"access.*control": "Access Control",
    r"unauthorized": "Access Control",
    r"unprotected": "Access Control",
    r"privilege": "Access Control",
    r"admin": "Access Control",
    r"ownership": "Access Control",
    r"permission": "Access Control",
    r"auth": "Access Control",
    r"lack.*of.*access": "Access Control",
    r"insufficient.*access": "Access Control",
    r"incorrect.*access": "Access Control",
    r"improper.*access": "Access Control",
    # Logic Flaw
    r"business.*logic": "Logic Flaw",
    r"logic.*flaw": "Logic Flaw",
    r"calculation": "Logic Flaw",
    r"logic.*error": "Logic Flaw",
    r"business.*rule": "Logic Flaw",
    r"bad.*logic": "Logic Flaw",
    r"business.*loigc": "Logic Flaw",  # Handle common typo
    r"bussiness.*logic": "Logic Flaw",  # Handle common typo
    r"incorrect.*logic": "Logic Flaw",
    r"improper.*logic": "Logic Flaw",
    # Precision
    r"rounding": "Precision",
    r"precision": "Precision",
    # Incorrect Validation
    r"insufficient.*validation": "Incorrect Validation",
    r"validation": "Incorrect Validation",
    r"improper.*validation": "Incorrect Validation",
    # Flash Loan Attack
    r"flash.*loan": "Flash Loan Attack",
    r"flashloan": "Flash Loan Attack",
    r"flash.*swap": "Flash Loan Attack",
    r"loan.*attack": "Flash Loan Attack",
    # Price Manipulation
    r"price.*manipulation": "Price Manipulation",
    r"oracle.*manipulation": "Price Manipulation",
    r"price.*oracle": "Price Manipulation",
    r"manipulation": "Price Manipulation",
    r"oracle.*attack": "Price Manipulation",
    r"price.*feed": "Price Manipulation",
    r"bad.*oracle": "Price Manipulation",
    r"pool.*manipulation": "Price Manipulation",
    r"pool.*imbalance": "Price Manipulation",
    r"pair.*manipulate": "Price Manipulation",
    # Reentrancy
    r"reentrancy": "Reentrancy Attack",
    r"re-entrancy": "Reentrancy Attack",
    r"reentrant": "Reentrancy Attack",
    r"read-only.*reentrancy": "Reentrancy Attack",
    r"cross.*contract.*reentrancy": "Reentrancy Attack",
    # Contract Vulnerability
    r"overflow": "Overflow",
    r"underflow": "Overflow",
    r"integer.*overflow": "Overflow",
    r"integer.*underflow": "Overflow",
    # Protocol Specific
    r"slippage": "Slippage Protection",
    r"storage.*collision": "Storage Collision",
    r"signature": "Signature Verification",
    r"verification": "Signature Verification",
    r"arbitrary.*calldata": "Arbitrary Calldata",
    r"arbitrary.*call": "Arbitrary Calldata",
    r"arbitrary.*yul": "Arbitrary Yul Calldata",
    r"weak.*random.*mint": "Weak Random Mint",
    r"arbitrary.*address": "Arbitrary Address Spoofing Attack",
    r"k-verification": "K-Verification",
    r"no.*slippage": "Slippage Protection",
    r"lack.*slippage": "Slippage Protection",
    # Social Engineering
    r"phishing": "Social Engineering",
    r"social": "Social Engineering",
    r"scam": "Social Engineering",
    r"fraud": "Social Engineering",
    r"impersonation": "Social Engineering",
    r"rugpull": "Social Engineering",
    # Implementation Bug
    r"bug": "Implementation Bug",
    r"error": "Implementation Bug",
    r"incorrect": "Implementation Bug",
    r"wrong": "Implementation Bug",
    r"implementation.*flaw": "Implementation Bug",
    r"coding.*error": "Implementation Bug",
    # Protocol Design
    r"design": "Protocol Design",
    r"architecture": "Protocol Design",
    r"specification": "Protocol Design",
    r"design.*flaw": "Protocol Design",
    # Front-running
    r"front.*run": "Front-running Attack",
    r"frontrun": "Front-running Attack",
    r"mev": "Front-running Attack",
    # Governance Attack
    r"governance": "Governance Attack",
    r"dao.*attack": "Governance Attack",
    r"voting": "Governance Attack",
    r"malicious.*proposal": "Governance Attack",
    # Sandwich Attack
    r"sandwich": "Sandwich Attack",
    # Bridge Attack
    r"bridge": "Bridge Attack",
    r"cross.*chain": "Bridge Attack",
    # Inflation Attack
    r"inflation.*attack": "Inflation Attack",
    r"compoundv2.*inflation": "Inflation Attack",
    # Precision Loss
    r"precision.*loss": "Precision Loss",
    r"loss.*of.*precision": "Precision Loss",
    # Self-Liquidation
    r"self.*liquidation": "Self-Liquidation",
    # Swap Metapool Attack
    r"swap.*metapool": "Swap Metapool Attack",
    # Private Key Compromised
    r"private.*key": "Private Key Compromised",
    r"key.*compromised": "Private Key Compromised",
    # Token Incompatible
    r"token.*incompatible": "Token Incompatible",
    r"incompatible.*token": "Token Incompatible",
    r"protocol.*token.*incompatible": "Protocol Token Incompatible",
    # Deflationary token uncompatible
    r"deflationary.*token": "Deflationary Token Incompatible",
    # Weak Random Numbers
    r"weak.*rng": "Weak RNG",
    r"bad.*randomness": "Weak RNG",
    r"predicting.*random": "Weak RNG",
    # Fake Market
    r"fake.*market": "Fake Market",
}


def normalize_attack_type(attack_type):
    if not attack_type:
        return "Unknown"

    attack_type = attack_type.lower().strip()
    attack_type = re.sub(r"^(attack|exploit|hack):?\s+", "", attack_type)

    for pattern, label in ATTACK_TYPE_MAPPING.items():
        if re.search(pattern, attack_type):
            return label

    return attack_type.title()
