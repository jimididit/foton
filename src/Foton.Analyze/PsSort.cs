using System;
using System.Collections.Generic;

namespace Foton.Analyze
{
    /// <summary>
    /// Sort-Object's order, including among equal keys. Windows PowerShell sorts with List.Sort, and powershell.exe
    /// does not target .NET 4.5+, so the runtime uses the legacy depth-limited quicksort (ArraySortHelper) rather
    /// than introsort. Same input and comparison here give the same output order as 1.38.x.
    /// </summary>
    static class PsSort
    {
        public static void Sort<T>(IList<T> keys, Comparison<T> compare)
        {
            if (keys.Count > 1) Quick(keys, 0, keys.Count - 1, compare, 32);
        }

        static void SwapIfGreater<T>(IList<T> k, Comparison<T> cmp, int a, int b)
        {
            if (a != b && cmp(k[a], k[b]) > 0) { var t = k[a]; k[a] = k[b]; k[b] = t; }
        }

        static void Quick<T>(IList<T> k, int left, int right, Comparison<T> cmp, int depthLimit)
        {
            do
            {
                if (depthLimit == 0) { HeapSort(k, left, right, cmp); return; }
                int i = left, j = right;
                int middle = i + ((j - i) >> 1);
                SwapIfGreater(k, cmp, i, middle);
                SwapIfGreater(k, cmp, i, j);
                SwapIfGreater(k, cmp, middle, j);
                var x = k[middle];
                do
                {
                    while (cmp(k[i], x) < 0) i++;
                    while (cmp(x, k[j]) < 0) j--;
                    if (i > j) break;
                    if (i < j) { var t = k[i]; k[i] = k[j]; k[j] = t; }
                    i++;
                    j--;
                } while (i <= j);
                depthLimit--;
                if (j - left <= right - i)
                {
                    if (left < j) Quick(k, left, j, cmp, depthLimit);
                    left = i;
                }
                else
                {
                    if (i < right) Quick(k, i, right, cmp, depthLimit);
                    right = j;
                }
            } while (left < right);
        }

        static void HeapSort<T>(IList<T> k, int lo, int hi, Comparison<T> cmp)
        {
            int n = hi - lo + 1;
            for (int i = n / 2; i >= 1; i--) DownHeap(k, i, n, lo, cmp);
            for (int i = n; i > 1; i--)
            {
                var t = k[lo]; k[lo] = k[lo + i - 1]; k[lo + i - 1] = t;
                DownHeap(k, 1, i - 1, lo, cmp);
            }
        }

        static void DownHeap<T>(IList<T> k, int i, int n, int lo, Comparison<T> cmp)
        {
            var d = k[lo + i - 1];
            while (i <= n / 2)
            {
                int child = 2 * i;
                if (child < n && cmp(k[lo + child - 1], k[lo + child]) < 0) child++;
                if (!(cmp(d, k[lo + child - 1]) < 0)) break;
                k[lo + i - 1] = k[lo + child - 1];
                i = child;
            }
            k[lo + i - 1] = d;
        }
    }
}
