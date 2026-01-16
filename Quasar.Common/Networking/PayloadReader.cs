using ProtoBuf;
using Quasar.Common.Cryptography;
using Quasar.Common.Messages;
using System;
using System.IO;

namespace Quasar.Common.Networking
{
    public class PayloadReader : MemoryStream
    {
        private readonly Stream _innerStream;
        private readonly Aes256 _aes;
        public bool LeaveInnerStreamOpen { get; }

        public PayloadReader(Stream stream, bool leaveInnerStreamOpen, string encryptionKey)
        {
            _innerStream = stream;
            LeaveInnerStreamOpen = leaveInnerStreamOpen;
            _aes = new Aes256(encryptionKey);
        }

        public PayloadReader(Stream stream, bool leaveInnerStreamOpen)
        {
            _innerStream = stream;
            LeaveInnerStreamOpen = leaveInnerStreamOpen;
        }

        public int ReadInteger()
        {
            return BitConverter.ToInt32(ReadBytes(4), 0);
        }

        public byte[] ReadBytes(int length)
        {
            if (_innerStream.Position + length <= _innerStream.Length)
            {
                byte[] result = new byte[length];
                _innerStream.Read(result, 0, result.Length);
                return result;
            }
            throw new OverflowException($"Unable to read {length} bytes from stream");
        }

        /// <summary>
        /// Reads the serialized message of the payload and deserializes it.
        /// </summary>
        /// <returns>The deserialized message of the payload.</returns>
        public IMessage ReadMessage()
        {
            // 스트림의 현재 위치부터 남은 데이터를 모두 읽음 (암호화된 본문)
            byte[] encryptedData = new byte[_innerStream.Length - _innerStream.Position];
            _innerStream.Read(encryptedData, 0, encryptedData.Length);

            // [핵심] 복호화 수행
            byte[] decryptedPayload = _aes.Decrypt(encryptedData);

            using (MemoryStream ms = new MemoryStream(decryptedPayload))
            {
                return Serializer.Deserialize<IMessage>(ms);
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
