class ComplianceRuleEngine:
    def __init__(self, rules):
        self.rules = rules

    def evaluate(self, resource):
        results = []
        for rule in self.rules:
            result = rule.evaluate(resource)
            results.append(result)
        return results

# Example usage
# rules = [Rule1(), Rule2()]
# engine = ComplianceRuleEngine(rules)
# results = engine.evaluate(resource)