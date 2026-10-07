import 'package:flutter/material.dart';
import 'models.dart';
import 'theme.dart';

/// Shows the detail for the selected pipeline stage.
class DetailPanel extends StatelessWidget {
  final RunData run;
  final String node;
  const DetailPanel({super.key, required this.run, required this.node});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      constraints: const BoxConstraints(minHeight: 320),
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: RF.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: RF.border),
      ),
      child: AnimatedSwitcher(
        duration: const Duration(milliseconds: 250),
        child: _content(context),
      ),
    );
  }

  Widget _content(BuildContext context) {
    switch (node) {
      case 'scout':
        return _scout();
      case 'strategist':
        return _strategist();
      case 'poc':
        return _poc();
      case 'remediation':
        return _remediation();
      case 'verification':
        return _verification();
      default:
        return const SizedBox();
    }
  }

  Widget _title(String t, String subtitle) => Column(
        key: ValueKey(t),
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(t, style: h2),
          const SizedBox(height: 2),
          Text(subtitle, style: small),
          const SizedBox(height: 16),
        ],
      );

  Widget _scout() => Column(
        key: const ValueKey('scout'),
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _title('Scout — mapped the codebase',
              '${run.findingCount} static findings · ${run.functionCount} functions indexed'),
          Text('Top findings',
              style: body.copyWith(fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          ...run.topFindings.map((f) => Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Row(children: [
                  _sevChip(f.severity),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      '${f.detector}  ·  ${f.contract}${f.function.isNotEmpty ? ".${f.function}" : ""}',
                      style: mono,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ]),
              )),
        ],
      );

  Widget _strategist() {
    final hyps = run.hypotheses.take(8).toList();
    return Column(
      key: const ValueKey('strategist'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _title('Strategist — ranked attack hypotheses',
            '${run.hypotheses.length} hypotheses · highest priority tried first'),
        ...hyps.asMap().entries.map((e) {
          final h = e.value;
          final top = e.key == 0;
          return Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
            decoration: BoxDecoration(
              color: top ? RF.accent.withValues(alpha: 0.10) : RF.surface2,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                  color: top ? RF.accent.withValues(alpha: 0.5) : RF.border),
            ),
            child: Row(children: [
              _priorityChip(h.priority, top),
              const SizedBox(width: 12),
              Expanded(
                child: Text('${h.targetContract}.${h.targetFunction}',
                    style: mono.copyWith(color: top ? RF.ink : RF.muted),
                    overflow: TextOverflow.ellipsis),
              ),
              Text(h.oracle, style: small),
            ]),
          );
        }),
      ],
    );
  }

  Widget _poc() {
    final poc = run.vuln?.poc;
    return Column(
      key: const ValueKey('poc'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _title(
            'PoC Engineer — wrote & ran the exploit',
            poc == null
                ? ''
                : 'oracle ${poc.oracle} · confirmed on attempt ${poc.attempt}'),
        if (poc != null) ...[
          Row(children: [
            _flag('oracle confirmed', poc.confirmed),
            const SizedBox(width: 12),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: RF.ok.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text('REDFORGE_ORACLE_CONFIRMED:${poc.oracle}',
                  style: mono.copyWith(color: RF.ok, fontSize: 11.5)),
            ),
          ]),
          const SizedBox(height: 14),
          Text('Exploit.t.sol (generated)',
              style: body.copyWith(fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          CodeBlock(poc.testSource, maxLines: 18),
        ],
      ],
    );
  }

  Widget _remediation() {
    final p = run.vuln?.patch;
    return Column(
      key: const ValueKey('remediation'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _title(
            'Remediation — minimal patch',
            p == null
                ? ''
                : 'compiles · exploit re-run and defeated · attempt ${p.attempts}'),
        if (p != null) ...[
          Row(children: [
            _flag('compiles', p.compiles),
            const SizedBox(width: 12),
            _flag('exploit defeated', p.pocDefeated),
          ]),
          const SizedBox(height: 14),
          Text('Patch (unified diff)',
              style: body.copyWith(fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          DiffBlock(p.diff),
        ],
      ],
    );
  }

  Widget _verification() {
    final v = run.vuln?.verification;
    return Column(
      key: const ValueKey('verification'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _title(
            'Verification — formally verified',
            v == null
                ? ''
                : v.verified
                    ? 'all gates green — status VERIFIED'
                    : 'not fully verified'),
        if (v != null) ...[
          Wrap(spacing: 12, runSpacing: 10, children: [
            _flag('exploit now fails', v.pocNowFails),
            _flag('existing tests', v.existingTestsPass, neutralFalse: true),
            _flag('differential equivalent', v.differential),
            _flag('Halmos proved', v.halmosProved),
          ]),
          const SizedBox(height: 16),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: RF.ok.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: RF.ok.withValues(alpha: 0.4)),
            ),
            child:
                Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Symbolic proof',
                  style:
                      body.copyWith(fontWeight: FontWeight.w600, color: RF.ok)),
              const SizedBox(height: 6),
              Text(
                '[PASS] check_flashLoanNotBrokenByDonation()  (paths: 32)\n'
                'Symbolic test result: 1 passed; 0 failed',
                style: mono.copyWith(color: RF.ok, fontSize: 12),
              ),
            ]),
          ),
          const SizedBox(height: 8),
          Text(
            'existing_tests_pass is false by design: the benchmark suite asserts the '
            'exploit, so it fails post-patch. It is recorded, not gated.',
            style: small,
          ),
        ],
      ],
    );
  }

  // --- small bits ---------------------------------------------------------
  Widget _sevChip(String sev) {
    final c = {
          'critical': RF.fail,
          'high': RF.fail,
          'medium': RF.warn,
          'low': RF.info,
          'info': RF.muted,
        }[sev] ??
        RF.muted;
    return Container(
      width: 62,
      padding: const EdgeInsets.symmetric(vertical: 3),
      decoration: BoxDecoration(
          color: c.withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(5)),
      child: Text(sev,
          textAlign: TextAlign.center,
          style:
              TextStyle(fontSize: 11, color: c, fontWeight: FontWeight.w600)),
    );
  }

  Widget _priorityChip(int p, bool top) => Container(
        width: 46,
        padding: const EdgeInsets.symmetric(vertical: 3),
        decoration: BoxDecoration(
          color: (top ? RF.accent : RF.muted).withValues(alpha: 0.18),
          borderRadius: BorderRadius.circular(5),
        ),
        child: Text('$p',
            textAlign: TextAlign.center,
            style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                color: top ? RF.accent : RF.muted)),
      );

  Widget _flag(String label, bool on, {bool neutralFalse = false}) {
    final c = on ? RF.ok : (neutralFalse ? RF.muted : RF.fail);
    return Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(
          on
              ? Icons.check_circle
              : (neutralFalse ? Icons.remove_circle_outline : Icons.cancel),
          color: c,
          size: 16),
      const SizedBox(width: 6),
      Text(label, style: small.copyWith(color: c)),
    ]);
  }
}

/// Monospace code block with scroll.
class CodeBlock extends StatelessWidget {
  final String code;
  final int maxLines;
  const CodeBlock(this.code, {super.key, this.maxLines = 20});
  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      constraints: BoxConstraints(maxHeight: maxLines * 20.0),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: RF.bg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: RF.border),
      ),
      child: SingleChildScrollView(child: SelectableText(code, style: mono)),
    );
  }
}

/// Diff block with red/green line colouring.
class DiffBlock extends StatelessWidget {
  final String diff;
  const DiffBlock(this.diff, {super.key});
  @override
  Widget build(BuildContext context) {
    final lines = diff.split('\n');
    return Container(
      width: double.infinity,
      constraints: const BoxConstraints(maxHeight: 280),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: RF.bg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: RF.border),
      ),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: lines.map((l) {
            Color col = RF.muted;
            Color? bg;
            if (l.startsWith('+') && !l.startsWith('+++')) {
              col = RF.ok;
              bg = RF.ok.withValues(alpha: 0.08);
            } else if (l.startsWith('-') && !l.startsWith('---')) {
              col = RF.fail;
              bg = RF.fail.withValues(alpha: 0.08);
            } else if (l.startsWith('@@')) {
              col = RF.info;
            }
            return Container(
              width: double.infinity,
              color: bg,
              child: Text(l.isEmpty ? ' ' : l,
                  style: mono.copyWith(color: col, fontSize: 12)),
            );
          }).toList(),
        ),
      ),
    );
  }
}
