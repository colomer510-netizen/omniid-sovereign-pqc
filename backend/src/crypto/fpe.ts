// Format-Preserving Encryption (FPE) simulated engine using LCG Permutations
// For OmniID structure: [Letra] + [6 números] + [Letra] + [7 números]
// Total combinations: 26 * 10^6 * 26 * 10^7 = 6,760,000,000,000,000

export class FormatPreservingEngine {
    private static readonly M = 6760000000000000n; // Módulo total
    
    // Parámetros del LCG que cumplen el Teorema de Hull-Dobell para un período completo
    // Factores primos de M: 2, 5, 13.
    // 1. c debe ser coprimo con M.
    // 2. a - 1 debe ser divisible por 2, 5 y 13 (por ende, por 130).
    // 3. Como M es divisible por 4, a - 1 debe ser divisible por 4.
    // Concluimos que a - 1 debe ser divisible por mcm(130, 4) = 260.
    private static readonly A = 400119250653980n * 260n + 1n; // a - 1 es múltiplo de 260
    private static readonly C = 9823901923910397n; // c es impar y coprimo con 5 y 13

    /**
     * Calcula el máximo común divisor
     */
    private static gcd(x: bigint, y: bigint): bigint {
        while (y !== 0n) {
            const temp = y;
            y = x % y;
            x = temp;
        }
        return x;
    }

    /**
     * Mapea un contador de forma determinista y biyectiva (cero colisiones) a un entero en [0, M-1]
     */
    public static encryptCounter(counter: number | bigint): bigint {
        const val = BigInt(counter) % this.M;
        
        // Verificación de coprimidad en tiempo de ejecución para asegurar la biyección matemática
        const divisor = this.gcd(this.C, this.M);
        if (divisor !== 1n) {
            throw new Error(`Falla crítica en FPE: C y M no son coprimos. GCD = ${divisor}`);
        }

        // Aplicamos la función de permutación LCG
        // f(x) = (a * x + c) mod M
        const permuted = (this.A * val + this.C) % this.M;
        return permuted;
    }

    /**
     * Convierte un entero permutado al formato OmniID: L-NNNNNN-L-NNNNNNN
     */
    public static integerToOmniID(val: bigint): string {
        let current = val;
        
        // 1. Primera letra (26 combinaciones)
        const l1Idx = Number(current % 26n);
        current /= 26n;
        
        // 2. Primer bloque de números (1,000,000 combinaciones)
        const n1Val = Number(current % 1000000n);
        current /= 1000000n;
        
        // 3. Segunda letra (26 combinaciones)
        const l2Idx = Number(current % 26n);
        current /= 26n;
        
        // 4. Segundo bloque de números (10,000,000 combinaciones)
        const n2Val = Number(current % 10000000n);
        
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const char1 = alphabet[l1Idx];
        const char2 = alphabet[l2Idx];
        
        const num1 = String(n1Val).padStart(6, '0');
        const num2 = String(n2Val).padStart(7, '0');
        
        return `${char1}${num1}${char2}${num2}`;
    }

    /**
     * Genera un identificador OmniID libre de colisiones para un contador dado
     */
    public static generateID(counter: number | bigint): { id: string; num: bigint } {
        const val = this.encryptCounter(counter);
        const id = this.integerToOmniID(val);
        return { id, num: val };
    }
}
