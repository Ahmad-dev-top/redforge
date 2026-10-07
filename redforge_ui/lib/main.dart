import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'models.dart';
import 'panels.dart';
import 'pipeline.dart';
import 'theme.dart';

void main() => runApp(const RedForgeApp());

class RedForgeApp extends StatelessWidget {
  const RedForgeApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RedForge',
      debugShowCheckedModeBanner: false,
      theme: RF.theme(),
      home: const Dashboard(),
    );
  }
}

class Dashboard extends StatefulWidget {
  const Dashboard({super.key});
  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard>
    with SingleTickerProviderStateMixin {
  RunData? run;
  String? error;
  String selected = 'verification'; // default to the payoff
  late AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this); // duration set per replay
    _load();
  }

  Future<void> _load() async {
    try {
      final raw = await rootBundle.loadString('assets/run.json');
      final data = RunData.fromJson(jsonDecode(raw) as Map<String, dynamic>);
      setState(() => run = data);
    } catch (e) {
      setState(() => error = '$e');
    }
  }

  void _replay() {
    final r = run;
    if (r == null) return;
    // Compress the real ~23min timeline into ~9s, proportional to real durations.
    _ctrl.duration = const Duration(milliseconds: 9000);
    _ctrl.forward(from: 0);
    setState(() => selected = 'scout');
    _ctrl.removeListener(_tick);
    _ctrl.addListener(_tick);
  }

  void _tick() {
    final r = run;
    if (r == null) return;
    final virtual = _ctrl.value * r.totalSeconds;
    // select the node currently active
    double acc = 0;
    String cur = 'scout';
    for (final n in nodeOrder) {
      final ev = r.events
          .firstWhere((e) => e.node == n, orElse: () => RunEvent(n, '', '', 0));
      if (virtual >= acc) cur = n;
      acc += ev.durationS;
    }
    if (cur != selected) setState(() => selected = cur);
    if (_ctrl.isCompleted) setState(() => selected = 'verification');
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (error != null) {
      return Scaffold(
          body: Center(
              child: Text('Failed to load run.json\n$error', style: body)));
    }
    final r = run;
    if (r == null) {
      return const Scaffold(
          body: Center(child: CircularProgressIndicator(color: RF.accent)));
    }
    final progress =
        _ctrl.isAnimating ? _ctrl.value * r.totalSeconds : double.infinity;

    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1080),
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 32),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _header(r),
                const SizedBox(height: 28),
                _card(
                    child: AnimatedBuilder(
                  animation: _ctrl,
                  builder: (_, __) => Pipeline(
                    run: r,
                    progress: progress,
                    selected: selected,
                    onSelect: (n) => setState(() => selected = n),
                  ),
                )),
                const SizedBox(height: 18),
                AnimatedBuilder(
                  animation: _ctrl,
                  builder: (_, __) => DetailPanel(run: r, node: selected),
                ),
                const SizedBox(height: 24),
                _footer(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _header(RunData r) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          const Icon(Icons.local_fire_department, color: RF.accent, size: 30),
          const SizedBox(width: 10),
          Text('RedForge', style: h1),
          const SizedBox(width: 14),
          _statusBadge(r.status),
          const Spacer(),
          _replayButton(),
        ]),
        const SizedBox(height: 10),
        Text(
          'Autonomous smart-contract auditor — found, proved, patched, and formally verified',
          style: small.copyWith(fontSize: 13.5),
        ),
        const SizedBox(height: 14),
        Wrap(spacing: 10, runSpacing: 10, children: [
          _stat('Target', r.repoUrl.replaceFirst('https://github.com/', '')),
          _stat('Cost', '\$${r.cost.toStringAsFixed(2)}'),
          _stat(
              'Total time', '${(r.totalSeconds / 60).toStringAsFixed(0)} min'),
          _stat('Findings', '${r.findingCount}'),
        ]),
      ],
    );
  }

  Widget _replayButton() => FilledButton.icon(
        onPressed: _replay,
        style: FilledButton.styleFrom(
          backgroundColor: RF.accent,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        ),
        icon: const Icon(Icons.play_arrow, size: 18),
        label: const Text('Replay pipeline'),
      );

  Widget _statusBadge(String s) {
    final c = RF.statusColor(s);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
      decoration: BoxDecoration(
        color: c.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: c.withValues(alpha: 0.6)),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(s == 'verified' ? Icons.verified : Icons.circle,
            color: c, size: 15),
        const SizedBox(width: 6),
        Text(s.toUpperCase(),
            style: TextStyle(
                color: c,
                fontWeight: FontWeight.w700,
                fontSize: 12,
                letterSpacing: 0.5)),
      ]),
    );
  }

  Widget _stat(String label, String value) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: RF.surface,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: RF.border),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Text('$label  ', style: small),
          Text(value, style: body.copyWith(fontWeight: FontWeight.w600)),
        ]),
      );

  Widget _card({required Widget child}) => Container(
        padding: const EdgeInsets.fromLTRB(22, 26, 22, 20),
        decoration: BoxDecoration(
          color: RF.surface,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: RF.border),
        ),
        child: child,
      );

  Widget _footer() => Row(children: [
        Text('Tap a stage to inspect · showcase replay of run ${run!.runId}',
            style: small),
        const Spacer(),
        Text(
            'harness-checked oracles · Halmos symbolic proof · no-network sandbox',
            style: small.copyWith(fontSize: 11)),
      ]);
}
