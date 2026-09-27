import json;
import sys;

# Recognized classes only. The generic UBSan token "undefined-behavior"
# is intentionally absent: clang 18 puts that token on SUMMARY lines even
# when the specific class is only named in the runtime error sentence.

glob ASAN_TYPES: list[str] = [
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-buffer-underflow",
    "stack-buffer-underflow",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "double-free",
    "alloc-dealloc-mismatch",
    "container-overflow",
    "negative-size-param",
    "initialization-order-fiasco",
    "dynamic-stack-buffer-overflow",
    "intra-object-overflow"
];

glob UBSAN_PHRASES: dict[str, str] = {
    "signed-integer-overflow": "signed integer overflow",
    "shift-exponent": "shift exponent",
    "invalid-shift-base": "left shift of negative",
    "integer-divide-by-zero": "division by zero",
    "alignment": "misaligned address",
    "null-pointer": "null pointer",
    "out-of-bounds": "out of bounds",
    "pointer-overflow": "pointer overflow",
    "unreachable": "execution reached an unreachable program point",
    "invalid-bool-load": "load of value",
    "invalid-enum-load": "load of value",
    "float-divide-by-zero": "division by zero"
};

glob HOSTILE: list[str] = [
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u200e",
    "\u200f",
    "\u061c",
    "\u2028",
    "\u2029",
    "\x1b",
    "<",
    ">",
    "&"
];

def is_bool(value: any) -> bool {
    return type(value) == bool;
}

def flag(evidence: dict, key: str) -> bool {
    if not (key in evidence) {
        return False;
    }
    value = evidence[key];
    if not is_bool(value) {
        return False;
    }
    return value == True;
}

def as_str(evidence: dict, key: str) -> str {
    if not (key in evidence) {
        return "";
    }
    value = evidence[key];
    if type(value) != str {
        return "";
    }
    return value;
}

def hostile(text: str) -> bool {
    for mark in HOSTILE {
        if mark in text {
            return True;
        }
    }
    for ch in text {
        code = ord(ch);
        if code < 32 or code == 127 {
            return True;
        }
    }
    return False;
}

def slen(text: str) -> int {
    count = 0;
    for ch in text {
        count += 1;
    }
    return count;
}

def even_hex(text: str) -> bool {
    count = 0;
    for ch in text {
        digit = (ch >= "0" and ch <= "9") or (ch >= "a" and ch <= "f");
        if not digit {
            return False;
        }
        count += 1;
    }
    if count < 2 or count > 16384 {
        return False;
    }
    return (count - ((count // 2) * 2)) == 0;
}

def known_sanitizer(evidence: dict) -> bool {
    sanitizer = as_str(evidence, "sanitizer");
    crash_type = as_str(evidence, "crash_type");
    excerpt = as_str(evidence, "report_excerpt");
    if crash_type == "" or crash_type == "undefined-behavior" {
        return False;
    }
    if sanitizer == "address" {
        for name in ASAN_TYPES {
            if name == crash_type {
                needle = "ERROR: AddressSanitizer: " + crash_type;
                return needle in excerpt;
            }
        }
        return False;
    }
    if sanitizer == "undefined" {
        if not ("UndefinedBehaviorSanitizer" in excerpt) {
            return False;
        }
        if not ("runtime error:" in excerpt) {
            return False;
        }
        if not (crash_type in UBSAN_PHRASES) {
            return False;
        }
        phrase = UBSAN_PHRASES[crash_type];
        return phrase in excerpt;
    }
    return False;
}

def classify_finding(evidence: dict) -> str {
    if type(evidence) != dict {
        return "Rejected";
    }
    excerpt = as_str(evidence, "report_excerpt");
    stack = as_str(evidence, "stack_trace");
    if slen(excerpt) > 20000 or slen(stack) > 20000 {
        return "Rejected";
    }
    if hostile(excerpt) or hostile(stack) {
        return "Rejected";
    }
    if flag(evidence, "rejected") {
        return "Rejected";
    }
    if flag(evidence, "simulated") {
        return "Sample";
    }
    if not even_hex(as_str(evidence, "input_hex")) {
        return "Unknown";
    }
    if excerpt == "" {
        return "Unknown";
    }
    rung = "Real crash captured";
    if flag(evidence, "reproduced") {
        rung = "Reproduced";
    } else {
        return rung;
    }
    if flag(evidence, "minimized") {
        rung = "Minimized";
    } else {
        return rung;
    }
    if not known_sanitizer(evidence) {
        return rung;
    }
    if as_str(evidence, "sanitizer") == "address" {
        rung = "Sanitizer-classified (ASan)";
    } else {
        rung = "Sanitizer-classified (UBSan)";
    }
    attested = flag(evidence, "attestation_verified");
    confirmed = flag(evidence, "artifact_verified") and flag(evidence, "workflow_corroborated") and ("#0" in stack) and stack != "";
    if confirmed {
        return "Confirmed";
    }
    if attested {
        return "Attested";
    }
    return rung;
}

with entry {
    raw = sys.stdin.read();
    payload = json.loads(raw);
    labels = [];
    for item in payload {
        labels.append(classify_finding(item));
    }
    print(json.dumps(labels));
}
