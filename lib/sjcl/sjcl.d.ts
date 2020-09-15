export = sjcl;
export as namespace sjcl;

declare namespace sjcl {
    export var bitArray: BitArrayStatic;
    export var codec: SjclCodecs;
    export var hash: SjclHashes;
    export var exception: SjclExceptions;
    export var cipher: SjclCiphers;
    export var mode: SjclModes;
    export var misc: SjclMisc;
    export var random: SjclRandom;
    export var prng: SjclRandomStatic;

    // ________________________________________________________________________

    interface BigNumber {
        radix: number;
        maxMul: number;

        copy(): BigNumber;

        /// Initializes this with it, either as a bn, a number, or a hex string.
        initWith: TypeHelpers.BigNumberBinaryOperator;

        /// Returns true if "this" and "that" are equal.  Calls fullReduce().
        /// Equality test is in constant time.
        equals(that: BigNumber | number): boolean;

        /// Get the i'th limb of this, zero if i is too large.
        getLimb(index: number): number;

        /// Constant time comparison function.
        /// Returns 1 if this >= that, or zero otherwise.
        greaterEquals(that: BigNumber | number): boolean;

        /// Convert to a hex string.
        toString(): string;

        /// this += that.  Does not normalize.
        addM: TypeHelpers.BigNumberBinaryOperator;

        /// this *= 2.  Requires normalized; ends up normalized.
        doubleM(): BigNumber;

        /// this /= 2, rounded down.  Requires normalized; ends up normalized.
        halveM(): BigNumber;

        /// this -= that.  Does not normalize.
        subM: TypeHelpers.BigNumberBinaryOperator;

        mod: TypeHelpers.BigNumberBinaryOperator;

        /// return inverse mod prime p.  p must be odd. Binary extended Euclidean algorithm mod p.
        inverseMod: TypeHelpers.BigNumberBinaryOperator;

        /// this + that.  Does not normalize.
        add: TypeHelpers.BigNumberBinaryOperator;

        /// this - that.  Does not normalize.
        sub: TypeHelpers.BigNumberBinaryOperator;

        /// this * that.  Normalizes and reduces.
        mul: TypeHelpers.BigNumberBinaryOperator;

        /// this ^ 2.  Normalizes and reduces.
        square(): BigNumber;

        /// this ^ n.  Uses square-and-multiply.  Normalizes and reduces.
        power(n: BigNumber | number[] | number): BigNumber;

        /// this * that mod N
        mulmod: TypeHelpers.BigNumberTrinaryOperator;

        /// this ^ x mod N
        powermod: TypeHelpers.BigNumberTrinaryOperator;

        /// this ^ x mod N with Montomery reduction
        montpowermod: TypeHelpers.BigNumberTrinaryOperator;

        trim(): BigNumber;

        /// Reduce mod a modulus.  Stubbed for subclassing.
        reduce(): BigNumber;

        /// Reduce and normalize.
        fullReduce(): BigNumber;

        /// Propagate carries.
        normalize(): BigNumber;

        /// Constant-time normalize. Does not allocate additional space.
        cnormalize(): BigNumber;

        /// Serialize to a bit array
        toBits(len?: number): BitArray;

        /// Return the length in bits, rounded up to the nearest byte.
        bitLength(): number;
    }

    interface BigNumberStatic {
        new (): BigNumber;
        new (n: BigNumber | number | string): BigNumber;

        fromBits(bits: BitArray): BigNumber;
        random: TypeHelpers.Bind1<number>;
        prime: {
            p127: PseudoMersennePrimeStatic;
            // Bernstein's prime for Curve25519
            p25519: PseudoMersennePrimeStatic;
            // Koblitz primes
            p192k: PseudoMersennePrimeStatic;
            p224k: PseudoMersennePrimeStatic;
            p256k: PseudoMersennePrimeStatic;
            // NIST primes
            p192: PseudoMersennePrimeStatic;
            p224: PseudoMersennePrimeStatic;
            p256: PseudoMersennePrimeStatic;
            p384: PseudoMersennePrimeStatic;
            p521: PseudoMersennePrimeStatic;
        };

        pseudoMersennePrime(exponent: number, coeff: number[][]): PseudoMersennePrimeStatic;
    }

    interface PseudoMersennePrime extends BigNumber {
        reduce(): PseudoMersennePrime;
        fullReduce(): PseudoMersennePrime;
        inverse(): PseudoMersennePrime;
    }

    interface PseudoMersennePrimeStatic extends BigNumberStatic {
        new (): PseudoMersennePrime;
        new (n: BigNumber | number | string): PseudoMersennePrime;
    }

    // ________________________________________________________________________

    interface BitArray extends Array<number> {}

    interface BitArrayStatic {
        /// Array slices in units of bits.
        bitSlice(a: BitArray, bstart: number, bend: number): BitArray;

        /// Extract a number packed into a bit array.
        extract(a: BitArray, bstart: number, blength: number): number;

        /// Concatenate two bit arrays.
        concat(a1: BitArray, a2: BitArray): BitArray;

        /// Find the length of an array of bits.
        bitLength(a: BitArray): number;

        /// Truncate an array.
        clamp(a: BitArray, len: number): BitArray;

        /// Make a partial word for a bit array.
        partial(len: number, x: number, _end?: number): number;

        /// Get the number of bits used by a partial word.
        getPartial(x: number): number;

        /// Compare two arrays for equality in a predictable amount of time.
        equal(a: BitArray, b: BitArray): boolean;

        /// Shift an array right.
        _shiftRight(a: BitArray, shift: number, carry?: number, out?: BitArray): BitArray;

        /// xor a block of 4 words together.
        _xor4(x: number[], y: number[]): number[];

        /// byteswap a word array inplace. (does not handle partial words)
        byteswapM(a: BitArray): BitArray;
    }

    // ________________________________________________________________________

    interface SjclCodec<T> {
        fromBits(bits: BitArray): T;
        toBits(value: T): BitArray;
    }

    interface SjclArrayBufferCodec extends SjclCodec<ArrayBuffer> {
        fromBits(bits: BitArray, padding?: boolean, padding_count?: number): ArrayBuffer;
        hexDumpBuffer(buffer: ArrayBuffer): void;
    }

    interface SjclCodecs {
        arrayBuffer: SjclArrayBufferCodec;
    }

    // ________________________________________________________________________

    interface SjclHash {
        reset(): SjclHash;
        update(data: BitArray | string): SjclHash;
        finalize(): BitArray;
    }

    interface SjclHashStatic {
        new (hash?: SjclHash): SjclHash;
        hash(data: BitArray | string): BitArray;
    }

    interface SjclHashes {
        sha1: SjclHashStatic;
        sha256: SjclHashStatic;
        sha512: SjclHashStatic;
        ripemd160: SjclHashStatic;
    }

    // ________________________________________________________________________

    interface SjclExceptions {
        corrupt: SjclExceptionFactory;
        invalid: SjclExceptionFactory;
        bug: SjclExceptionFactory;
        notReady: SjclExceptionFactory;
    }

    interface SjclExceptionFactory {
        new (message: string): Error;
    }

    // ________________________________________________________________________

    interface SjclCiphers {
        aes: SjclCipherStatic;
    }

    interface SjclCipher {
        encrypt(data: number[]): number[];
        decrypt(data: number[]): number[];
    }

    interface SjclCipherStatic {
        new (key: number[]): SjclCipher;
    }

    // ________________________________________________________________________

    interface SjclModes {
        cbc: SjclCBCMode;
    }

    interface SjclCBCMode {
        encrypt(prf: SjclCipher, plaintext: BitArray, iv: BitArray, adata?: BitArray): BitArray;
        decrypt(prf: SjclCipher, ciphertext: BitArray, iv: BitArray, adata?: BitArray): BitArray;
    }

    // ________________________________________________________________________

    interface PBKDF2Params {
        iter?: number;
        salt?: BitArray;
    }

    interface SjclMisc {
        pbkdf2(
            password: BitArray | string,
            salt: BitArray | string,
            count?: number,
            length?: number,
            Prff?: SjclPRFFamilyStatic,
        ): BitArray;
        hmac: SjclHMACStatic;
        cachedPbkdf2(
            password: string,
            obj?: PBKDF2Params,
        ): {
            key: BitArray;
            salt: BitArray;
        };
        hkdf(
            ikm: BitArray,
            keyBitLength: number,
            salt: BitArray | string,
            info: BitArray | string,
            Hash?: SjclHashStatic,
        ): BitArray;
        scrypt(
            password: BitArray | string,
            salt: BitArray | string,
            N?: number,
            r?: number,
            p?: number,
            length?: number,
            Prff?: SjclPRFFamilyStatic,
        ): BitArray;
    }

    class SjclPRFFamily {
        encrypt(data: BitArray | string): BitArray;
    }

    interface SjclHMAC extends SjclPRFFamily {
        mac(data: BitArray | string): BitArray;
        reset(): void;
        update(data: BitArray | string): void;
        digest(): BitArray;
    }

    interface SjclPRFFamilyStatic {
        new (key: BitArray): SjclPRFFamily;
    }

    interface SjclHMACStatic {
        new (key: BitArray, Hash?: SjclHashStatic): SjclHMAC;
    }

    // ________________________________________________________________________


    interface SjclRandom {
        randomWords(nwords: number, paranoia?: number): BitArray;
        setDefaultParanoia(paranoia: number, allowZeroParanoia: string): void;
        addEntropy(data: number | number[] | string, estimatedEntropy: number, source: string): void;
        isReady(paranoia?: number): boolean;
        getProgress(paranoia?: number): number;
        startCollectors(): void;
        stopCollectors(): void;
        addEventListener(name: string, cb: Function): void;
        removeEventListener(name: string, cb: Function): void;
    }

    interface SjclRandomStatic {
        new (defaultParanoia: number): SjclRandom;
    }

    // ________________________________________________________________________

    interface SjclCipherParams {
        v?: number;
        iter?: number;
        ks?: number;
        ts?: number;
        mode?: string;
        adata?: string;
        cipher?: string;
    }

    interface SjclCipherEncryptParams extends SjclCipherParams {
        salt: BitArray;
        iv: BitArray;
    }

    interface SjclCipherDecryptParams extends SjclCipherParams {
        salt?: BitArray;
        iv?: BitArray;
    }

    interface SjclCipherEncrypted extends SjclCipherEncryptParams {
        kemtag?: BitArray;
        ct: BitArray;
    }

    interface SjclCipherDecrypted extends SjclCipherEncrypted {
        key: BitArray;
    }

    // ________________________________________________________________________

    namespace TypeHelpers {
        interface One<T> {
            (value: T): BigNumber;
        }

        interface BigNumberBinaryOperator extends One<number>, One<string>, One<BigNumber> {}

        interface Two<T1, T2> {
            (x: T1, N: T2): BigNumber;
        }

        interface Bind1<T> extends Two<number, T>, Two<string, T>, Two<BigNumber, T> {}

        interface BigNumberTrinaryOperator extends Bind1<number>, Bind1<string>, Bind1<BigNumber> {}
    }
}
