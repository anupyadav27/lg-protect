# Security Expert ID Structure Analysis & Design

## Approach: Add unique_key Field (Preserving Existing IDs)

**Strategy**: Instead of modifying existing IDs, we add a new `unique_key` field to each compliance requirement. This preserves backward compatibility while providing global uniqueness and navigation capabilities.

**Naming Convention**: All unique_key values use lowercase with underscores for programming-friendly naming (e.g., `cisa_sys_001_001` instead of `CISA_SYS_001_001`).

## Current ID Pattern Analysis

### 1. CISA (Cybersecurity & Infrastructure Security Agency)
**Current Pattern**: `your-systems-1`, `your-surroundings-2`, `your-data-1`
**Issues**: 
- Not hierarchical
- Descriptive but not systematic
- No clear categorization

**Proposed unique_key Structure**: `cisa_sys_001_001`, `cisa_sur_001_002`, `cisa_data_001_001`
- `cisa` = Framework prefix (lowercase)
- `sys` = Systems category (lowercase)
- `sur` = Surroundings category (lowercase)
- `data` = Data category (lowercase)
- `001` = Section number
- `001` = Sequential number within category

### 2. SOC2 (System and Organization Controls)
**Current Pattern**: `cc_1_3`, `cc_2_1`, `cc_3_1`
**Issues**:
- Good hierarchical structure
- Abbreviations not intuitive
- Missing framework prefix

**Proposed unique_key Structure**: `soc2_cc_001_003_001`, `soc2_cc_002_001_001`
- `soc2` = Framework prefix (lowercase)
- `cc` = Common Criteria (lowercase)
- `001` = Major section (1 = Control Environment)
- `003` = Sub-section (3 = Principle 3)
- `001` = Sequential number

### 3. PCI DSS (Payment Card Industry)
**Current Pattern**: `1.2.5.1`, `1.2.5.2`
**Issues**:
- Good hierarchical structure
- Missing framework prefix
- Could be more descriptive

**Proposed unique_key Structure**: `pci_net_001_002_005_001`
- `pci` = Framework prefix (lowercase)
- `net` = Network Security category (lowercase)
- `001` = Requirement 1 (Build and Maintain a Secure Network)
- `002` = Sub-requirement 2 (Network Security Controls)
- `005` = Control 5 (Network Security Controls)
- `001` = Specific check 1

### 4. NIST-CSF (National Institute of Standards and Technology)
**Current Pattern**: `ae_1`, `cm_1`, `cm_2`
**Issues**:
- Too abbreviated
- Not intuitive
- Missing framework prefix

**Proposed unique_key Structure**: `nist_de_ae_001`, `nist_de_cm_001`
- `nist` = Framework prefix (lowercase)
- `de` = Detect function (lowercase)
- `ae` = Anomalies and Events (lowercase)
- `cm` = Continuous Monitoring (lowercase)
- `001` = Sequential number

### 5. HIPAA (Health Insurance Portability and Accountability Act)
**Current Pattern**: `164_308_a_1_ii_a`
**Issues**:
- Legal reference format
- Not intuitive for technical implementation
- Missing framework prefix

**Proposed unique_key Structure**: `hipaa_adm_164_308_a_001_ii_a`
- `hipaa` = Framework prefix (lowercase)
- `adm` = Administrative Safeguards (lowercase)
- `164` = Part 164
- `308` = Section 308
- `a` = Subsection A (lowercase)
- `001` = Paragraph 1
- `ii` = Subparagraph II (lowercase)
- `a` = Item A (lowercase)

### 6. CIS (Center for Internet Security)
**Current Pattern**: `1.1`, `1.2`, `1.3`
**Issues**:
- Good hierarchical structure
- Missing framework prefix
- Could be more descriptive

**Proposed unique_key Structure**: `cis_iam_001_001`, `cis_iam_001_002`
- `cis` = Framework prefix (lowercase)
- `iam` = Identity and Access Management category (lowercase)
- `001` = Section 1 (Identity and Access Management)
- `001` = Control 1 (Maintain current contact details)

## Recommended unique_key Structure

### Format: `framework_category_major_minor_sequential`

**Components**:
1. **framework**: 3-4 letter code (cisa, soc2, pci, nist, hipaa, cis) - lowercase
2. **category**: 2-3 letter code for major functional area - lowercase
3. **major**: 3-digit number for major section
4. **minor**: 3-digit number for sub-section
5. **sequential**: 3-digit number for specific control

**Examples**:
- `cisa_sys_001_000_001` = CISA Systems category, section 1, control 1
- `soc2_cc_001_003_000` = SOC2 Common Criteria, section 1, principle 3
- `pci_net_001_002_005` = PCI Network Security, requirement 1, sub-requirement 2, control 5
- `nist_de_ae_001_000` = NIST Detect function, Anomalies category, control 1
- `hipaa_adm_164_308_001` = HIPAA Administrative Safeguards, section 164.308, control 1
- `cis_iam_001_001_000` = CIS Identity and Access Management, section 1, control 1

### Benefits of This Structure:

1. **Backward Compatibility**: Existing IDs remain unchanged
2. **Global Uniqueness**: Each unique_key is globally unique across all frameworks
3. **Hierarchical**: Clear parent-child relationships
4. **Intuitive**: Framework and category are immediately recognizable
5. **Extensible**: Can accommodate new frameworks and categories
6. **Sortable**: Natural sorting order
7. **Searchable**: Easy to filter by framework, category, or section
8. **Versionable**: Can add version suffix if needed (e.g., `_v4.0`)
9. **Programming Friendly**: Lowercase with underscores for easy use in code

### Implementation Strategy:

1. **Phase 1**: Add unique_key field to each compliance requirement
2. **Phase 2**: Create lookup table for easy navigation
3. **Phase 3**: Implement search and filter capabilities
4. **Phase 4**: Add validation and consistency checks

### JSON Structure Example:

```json
{
  "Id": "your-systems-1",           // Original ID (unchanged)
  "unique_key": "cisa_sys_001_001", // New unique identifier (lowercase)
  "Name": "Your Systems-1",
  "Description": "Learn what is on your network...",
  "Attributes": [...],
  "Checks": [...]
}
```

### Usage Examples:

```python
# Direct lookup by unique_key
compliance_item = lookup_table["cisa_sys_001_001"]

# Filter by framework
cisa_items = [item for item in all_items if item.unique_key.startswith("cisa_")]

# Filter by category
system_items = [item for item in all_items if "sys" in item.unique_key]

# Search across all frameworks
network_security = [item for item in all_items if "net" in item.unique_key]

# Easy variable naming in code
cisa_sys_001_001 = lookup_table["cisa_sys_001_001"]
pci_net_001_002_005 = lookup_table["pci_net_001_002_005"]
```

### Validation Rules:

1. Framework codes must be 3-4 characters, lowercase
2. Category codes must be 2-3 characters, lowercase
3. All numeric components must be 3 digits, zero-padded
4. Total unique_key length should not exceed 25 characters
5. No special characters except underscores
6. Must be unique across all compliance files
7. Original ID field remains unchanged for backward compatibility
8. All components use lowercase for programming compatibility

### Script Usage:

```bash
# Preview what unique_key fields would be added
python implement_security_expert_ids.py --preview

# Add unique_key fields to all files
python implement_security_expert_ids.py

# Create lookup table for navigation
python implement_security_expert_ids.py --lookup
``` 