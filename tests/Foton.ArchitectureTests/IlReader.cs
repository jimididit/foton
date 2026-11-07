using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// Walks a method body instruction by instruction (opcode table from System.Reflection.Emit.OpCodes),
    /// so operand bytes are never mistaken for opcodes. Fails closed: an unknown opcode or a method
    /// operand that does not resolve throws, rather than being skipped.
    /// </summary>
    static class IlReader
    {
        static readonly Dictionary<short, OpCode> Codes = typeof(OpCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(f => (OpCode)f.GetValue(null)!)
            .ToDictionary(o => o.Value);

        /// <summary>Every method referenced by an InlineMethod operand (call, callvirt, newobj, ldftn, ldvirtftn, jmp).</summary>
        public static IEnumerable<MethodBase> Callees(MethodBase m)
        {
            var il = m.GetMethodBody()?.GetILAsByteArray();
            if (il == null) yield break; // abstract, extern, or runtime-implemented: no IL to scan
            var typeArgs = m.DeclaringType != null && m.DeclaringType.IsGenericType ? m.DeclaringType.GetGenericArguments() : null;
            var methodArgs = m.IsGenericMethod ? m.GetGenericArguments() : null;

            int i = 0;
            while (i < il.Length)
            {
                short value = il[i++];
                if (value == 0xFE) value = (short)(0xFE00 | il[i++]);
                if (!Codes.TryGetValue(value, out var op))
                    throw new InvalidOperationException($"Unknown IL opcode 0x{value:X} at {i} in {m.DeclaringType}.{m.Name}.");

                switch (op.OperandType)
                {
                    case OperandType.InlineMethod:
                        int token = BitConverter.ToInt32(il, i);
                        // Throws if the token does not resolve: fail closed.
                        yield return m.Module.ResolveMethod(token, typeArgs, methodArgs)!;
                        i += 4;
                        break;
                    case OperandType.InlineNone:
                        break;
                    case OperandType.ShortInlineBrTarget:
                    case OperandType.ShortInlineI:
                    case OperandType.ShortInlineVar:
                        i += 1;
                        break;
                    case OperandType.InlineVar:
                        i += 2;
                        break;
                    case OperandType.InlineI8:
                    case OperandType.InlineR:
                        i += 8;
                        break;
                    case OperandType.InlineSwitch:
                        int count = BitConverter.ToInt32(il, i);
                        i += 4 + 4 * count;
                        break;
                    default: // InlineBrTarget, InlineField, InlineI, InlineSig, InlineString, InlineTok, InlineType, ShortInlineR
                        i += 4;
                        break;
                }
            }
        }
    }
}
