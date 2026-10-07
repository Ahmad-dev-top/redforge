import 'package:flutter/material.dart';

/// RedForge palette — dark, forge-red accent.
class RF {
  static const bg = Color(0xFF0D0D10);
  static const surface = Color(0xFF16161B);
  static const surface2 = Color(0xFF1E1E26);
  static const border = Color(0xFF2A2A33);
  static const ink = Color(0xFFECECEF);
  static const muted = Color(0xFF9A9AA6);

  static const accent = Color(0xFFC8341F); // forge red
  static const accentDim = Color(0xFF7A2114);

  // status colours
  static const ok = Color(0xFF3FB950); // verified / pass
  static const warn = Color(0xFFD29922); // confirmed / patched
  static const info = Color(0xFF58A6FF); // mapped / neutral
  static const fail = Color(0xFFF85149);

  static const mono = 'monospace';

  static Color statusColor(String s) {
    switch (s) {
      case 'verified':
        return ok;
      case 'patched':
      case 'exploit_confirmed':
      case 'hypotheses_ready':
        return warn;
      case 'mapped':
        return info;
      case 'failed':
        return fail;
      default:
        return muted;
    }
  }

  static ThemeData theme() {
    final base = ThemeData.dark(useMaterial3: true);
    return base.copyWith(
      scaffoldBackgroundColor: bg,
      colorScheme: base.colorScheme.copyWith(
        primary: accent,
        surface: surface,
      ),
      textTheme: base.textTheme.apply(bodyColor: ink, displayColor: ink),
    );
  }
}

TextStyle h1 = const TextStyle(
    fontSize: 30,
    fontWeight: FontWeight.w700,
    color: RF.ink,
    letterSpacing: -0.5);
TextStyle h2 =
    const TextStyle(fontSize: 17, fontWeight: FontWeight.w600, color: RF.ink);
TextStyle body = const TextStyle(fontSize: 14, color: RF.ink, height: 1.45);
TextStyle small = const TextStyle(fontSize: 12.5, color: RF.muted);
TextStyle mono = const TextStyle(
    fontFamily: RF.mono, fontSize: 12.5, color: RF.ink, height: 1.5);
