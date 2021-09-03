import YNEvents from '@yesness/events';
import { IYNSocket } from '@yesness/socket';
import { ICryptico, RSAKey } from './cryptico';

export type YNRSA = {
    /**
     * Our public key that we send to the other socket. They
     * encrypt all data they send to us with this key.
     */
    publicKey: string;
    /**
     * Encrypts data using the public key from the argument. This data should also be signed with
     * our private key.
     * @param data Unencrypted data that should be encrypted with the public key from the 2nd argument
     * @param publicKey The public key of the other socket used to encrypted all data we send to them.
     */
    encrypt(data: string, publicKey: string): string;
    /**
     * Decrypts all incoming data that has been encrypted with our public key.
     * This data was also signed with the other socket's private key, so we can validate
     * it against the expectedPublicKey argument.
     * @param data Data that has been encrypted with our public key.
     * @param expectedPublicKey The public key of the other socket.
     */
    decrypt(data: string, expectedPublicKey: string): string;
    /**
     * Default: 'utf-8'
     * All buffer to/from string conversions will use this encoding.
     */
    encoding?: BufferEncoding;
};

class RSASocket extends YNEvents implements IYNSocket {
    static async init(socket: IYNSocket, rsa: YNRSA) {
        socket.send(rsa.publicKey);
        const publicKeyBuffer = await this.onceData(socket);
        return new RSASocket(socket, publicKeyBuffer.toString(), rsa);
    }

    private static onceData(socket: IYNSocket): Promise<Buffer> {
        return new Promise((resolve) => {
            socket.once('data', resolve);
        });
    }

    private encoding: BufferEncoding;

    private constructor(
        private socket: IYNSocket,
        private otherPublicKey: string,
        private rsa: YNRSA
    ) {
        super();
        this.encoding = rsa.encoding ?? 'utf-8';
        this.socket.on('data', (data: Buffer) => {
            const decrypted = this.rsa.decrypt(
                data.toString(),
                this.otherPublicKey
            );
            this.emit('data', Buffer.from(decrypted, this.encoding));
        });
        this.socket.on('close', () => this.emit('close'));
    }

    send(data: Buffer) {
        this.socket.send(
            this.rsa.encrypt(data.toString(this.encoding), this.otherPublicKey)
        );
    }

    close() {
        this.socket.close();
    }
}

export default class YNRSASocket {
    static async create(socket: IYNSocket, rsa: YNRSA): Promise<IYNSocket> {
        return await RSASocket.init(socket, rsa);
    }

    static async cryptico(
        socket: IYNSocket,
        config: {
            cryptico: ICryptico;
            privateKey: RSAKey;
            encoding?: BufferEncoding;
        }
    ): Promise<IYNSocket> {
        const { cryptico, privateKey, encoding } = config;
        return await YNRSASocket.create(socket, {
            publicKey: cryptico.publicKeyString(privateKey),
            encrypt(data: string, publicKey: string) {
                const encrypted = cryptico.encrypt(data, publicKey, privateKey);
                if (encrypted.status !== 'success') {
                    throw new Error('Encryption failed');
                }
                return encrypted.cipher;
            },
            decrypt(data: string, expectedPublicKey: string) {
                const decrypted = cryptico.decrypt(data, privateKey);
                if (decrypted.status !== 'success') {
                    throw new Error('Decryption failed');
                }
                if (decrypted.signature !== 'verified') {
                    throw new Error('Decryption not verified');
                }
                if (decrypted.publicKeyString !== expectedPublicKey) {
                    throw new Error('Expected public key did not match');
                }
                return decrypted.plaintext;
            },
            encoding,
        });
    }
}
