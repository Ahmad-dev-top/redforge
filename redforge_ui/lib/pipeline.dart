import 'package:flutter/material.dart';
import 'models.dart';
import 'theme.dart';

const nodeOrder = ['scout', 'strategist', 'poc', 'remediation', 'verification'];
const nodeLabels = {
  'scout': 'Scout',
  'strategist': 'Strategist',
  'poc': 'PoC Engineer',
  'remediation': 'Remediation',
  'verification': 'Verification',
};
const nodeIcons = {
  'scout': Icons.travel_explore,
  'strategist': Icons.psychology_alt,
  'poc': Icons.bolt,
  'remediation': Icons.healing,
  'verification': Icons.verified_user,
};

/// The five-stage pipeline. `progress` is virtual seconds elapsed during replay
/// (or [double.infinity] for the static, all-complete view). Tapping a stage
/// calls [onSelect].
class Pipeline extends StatelessWidget {
  final RunData run;
  final double progress; // virtual seconds, or infinity when done
  final String selected;
  final ValueChanged<String> onSelect;

  const Pipeline({
    super.key,
    required this.run,
    required this.progress,
    required this.selected,
    required this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    // cumulative timeline from event durations
    final byNode = {for (final e in run.events) e.node: e};
    double acc = 0;
    final spans = <String, List<double>>{};
    for (final n in nodeOrder) {
      final d = byNode[n]?.durationS ?? 0;
      spans[n] = [acc, acc + d];
      acc += d;
    }

    return LayoutBuilder(builder: (context, c) {
      final tight = c.maxWidth < 760;
      return Row(
        children: [
          for (int i = 0; i < nodeOrder.length; i++) ...[
            Expanded(
              child: _node(
                nodeOrder[i],
                byNode[nodeOrder[i]],
                spans[nodeOrder[i]]!,
                tight,
              ),
            ),
            if (i < nodeOrder.length - 1) _connector(spans[nodeOrder[i]]![1]),
          ]
        ],
      );
    });
  }

  // state of a node given replay progress
  int _state(List<double> span) {
    if (progress == double.infinity || progress >= span[1]) return 2; // done
    if (progress >= span[0]) return 1; // active
    return 0; // pending
  }

  Widget _connector(double doneAt) {
    final filled = progress == double.infinity || progress >= doneAt;
    return Container(
      width: 28,
      height: 3,
      margin: const EdgeInsets.only(bottom: 44),
      decoration: BoxDecoration(
        color: filled ? RF.accent : RF.border,
        borderRadius: BorderRadius.circular(2),
      ),
    );
  }

  Widget _node(String node, RunEvent? ev, List<double> span, bool tight) {
    final st = _state(span);
    final isSel = selected == node;
    final statusColor = ev != null ? RF.statusColor(ev.status) : RF.muted;
    final glow = st == 1;
    final done = st == 2;

    final circleColor = st == 0
        ? RF.surface2
        : done
            ? statusColor.withValues(alpha: 0.18)
            : RF.accent.withValues(alpha: 0.22);
    final borderColor = st == 0
        ? RF.border
        : done
            ? statusColor
            : RF.accent;

    return GestureDetector(
      onTap: done ? () => onSelect(node) : null,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 250),
        padding: const EdgeInsets.symmetric(vertical: 6),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSel ? RF.accent : Colors.transparent,
            width: 1.2,
          ),
        ),
        child: Column(
          children: [
            AnimatedContainer(
              duration: const Duration(milliseconds: 300),
              width: 54,
              height: 54,
              decoration: BoxDecoration(
                color: circleColor,
                shape: BoxShape.circle,
                border: Border.all(color: borderColor, width: 2),
                boxShadow: glow
                    ? [
                        BoxShadow(
                            color: RF.accent.withValues(alpha: 0.5),
                            blurRadius: 16,
                            spreadRadius: 1)
                      ]
                    : null,
              ),
              child: Icon(
                done && ev?.status == 'verified'
                    ? Icons.check
                    : nodeIcons[node],
                color: st == 0 ? RF.muted : borderColor,
                size: 24,
              ),
            ),
            const SizedBox(height: 8),
            Text(nodeLabels[node]!,
                style: TextStyle(
                  fontSize: tight ? 11 : 13,
                  fontWeight: FontWeight.w600,
                  color: st == 0 ? RF.muted : RF.ink,
                )),
            const SizedBox(height: 2),
            Text(
              ev == null ? '' : '${ev.durationS.toStringAsFixed(0)}s',
              style: TextStyle(
                  fontSize: 11, color: st == 0 ? RF.border : RF.muted),
            ),
          ],
        ),
      ),
    );
  }
}
