// Models for the exported AuditState run.json. Parsed defensively — fields may
// be absent in older checkpoints.

class RunData {
  final String repoUrl;
  final String runId;
  final String status;
  final double cost;
  final int findingCount;
  final int functionCount;
  final List<Hypothesis> hypotheses;
  final List<Finding> topFindings;
  final Vulnerability? vuln;
  final List<RunEvent> events;

  RunData({
    required this.repoUrl,
    required this.runId,
    required this.status,
    required this.cost,
    required this.findingCount,
    required this.functionCount,
    required this.hypotheses,
    required this.topFindings,
    required this.vuln,
    required this.events,
  });

  double get totalSeconds => events.fold(0.0, (a, e) => a + e.durationS);

  static int _sevRank(String s) =>
      const {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
      }[s] ??
      1;

  factory RunData.fromJson(Map<String, dynamic> j) {
    final findings = (j['findings'] as List? ?? [])
        .map((f) => Finding.fromJson(f as Map<String, dynamic>))
        .toList();
    findings.sort((a, b) {
      final r = _sevRank(b.severity).compareTo(_sevRank(a.severity));
      return r != 0 ? r : b.confidence.compareTo(a.confidence);
    });
    final hyps = (j['hypotheses'] as List? ?? [])
        .map((h) => Hypothesis.fromJson(h as Map<String, dynamic>))
        .toList()
      ..sort((a, b) => b.priority.compareTo(a.priority));
    final vulns = (j['vulnerabilities'] as List? ?? []);
    return RunData(
      repoUrl: j['repo_url']?.toString() ?? '',
      runId: j['run_id']?.toString() ?? '',
      status: j['status']?.toString() ?? '',
      cost: (j['token_cost_usd'] as num?)?.toDouble() ?? 0,
      findingCount: findings.length,
      functionCount: (j['functions'] as List?)?.length ?? 0,
      hypotheses: hyps,
      topFindings: findings.take(8).toList(),
      vuln: vulns.isNotEmpty
          ? Vulnerability.fromJson(vulns.first as Map<String, dynamic>)
          : null,
      events: (j['events'] as List? ?? [])
          .map((e) => RunEvent.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }
}

class RunEvent {
  final String node;
  final String status;
  final String summary;
  final double durationS;
  RunEvent(this.node, this.status, this.summary, this.durationS);
  factory RunEvent.fromJson(Map<String, dynamic> j) => RunEvent(
        j['node']?.toString() ?? '',
        j['status']?.toString() ?? '',
        j['summary']?.toString() ?? '',
        (j['duration_s'] as num?)?.toDouble() ?? 0,
      );
}

class Finding {
  final String detector, severity, contract, function, vulnClass;
  final double confidence;
  Finding(this.detector, this.severity, this.contract, this.function,
      this.vulnClass, this.confidence);
  factory Finding.fromJson(Map<String, dynamic> j) => Finding(
        j['detector']?.toString() ?? '',
        j['severity']?.toString() ?? 'info',
        j['contract']?.toString() ?? '',
        j['function']?.toString() ?? '',
        j['vuln_class']?.toString() ?? 'other',
        (j['confidence'] as num?)?.toDouble() ?? 0,
      );
}

class Hypothesis {
  final String targetContract, targetFunction, vulnClass, oracle, rationale;
  final int priority;
  Hypothesis(this.targetContract, this.targetFunction, this.vulnClass,
      this.oracle, this.rationale, this.priority);
  factory Hypothesis.fromJson(Map<String, dynamic> j) => Hypothesis(
        j['target_contract']?.toString() ?? '',
        j['target_function']?.toString() ?? '',
        j['vuln_class']?.toString() ?? '',
        j['oracle']?.toString() ?? '',
        j['rationale']?.toString() ?? '',
        (j['priority'] as num?)?.toInt() ?? 0,
      );
}

class Vulnerability {
  final Poc? poc;
  final Patch? patch;
  final Verification? verification;
  Vulnerability(this.poc, this.patch, this.verification);
  factory Vulnerability.fromJson(Map<String, dynamic> j) => Vulnerability(
        j['poc'] != null ? Poc.fromJson(j['poc']) : null,
        j['patch'] != null ? Patch.fromJson(j['patch']) : null,
        j['verification'] != null
            ? Verification.fromJson(j['verification'])
            : null,
      );
}

class Poc {
  final String oracle, testSource, traceExcerpt;
  final bool confirmed;
  final int attempt;
  Poc(this.oracle, this.testSource, this.traceExcerpt, this.confirmed,
      this.attempt);
  factory Poc.fromJson(Map<String, dynamic> j) => Poc(
        j['oracle']?.toString() ?? '',
        j['test_source']?.toString() ?? '',
        j['trace_excerpt']?.toString() ?? '',
        j['oracle_confirmed'] == true,
        (j['attempt'] as num?)?.toInt() ?? 0,
      );
}

class Patch {
  final String diff;
  final bool compiles, pocDefeated;
  final int attempts;
  Patch(this.diff, this.compiles, this.pocDefeated, this.attempts);
  factory Patch.fromJson(Map<String, dynamic> j) => Patch(
        j['diff']?.toString() ?? '',
        j['compiles'] == true,
        j['poc_defeated'] == true,
        (j['attempts'] as num?)?.toInt() ?? 0,
      );
}

class Verification {
  final bool pocNowFails,
      existingTestsPass,
      differential,
      halmosProved,
      halmosTimedOut,
      verified;
  final String counterexample;
  Verification(
      this.pocNowFails,
      this.existingTestsPass,
      this.differential,
      this.halmosProved,
      this.halmosTimedOut,
      this.verified,
      this.counterexample);
  factory Verification.fromJson(Map<String, dynamic> j) => Verification(
        j['poc_now_fails'] == true,
        j['existing_tests_pass'] == true,
        j['differential_equivalent'] == true,
        j['halmos_proved'] == true,
        j['halmos_timed_out'] == true,
        j['verified'] == true,
        j['halmos_counterexample']?.toString() ?? '',
      );
}
