using ProtoBuf;
using Quasar.Common.Messages;
using System;
using System.IO;

namespace Quasar.Common.Networking
{
    public class PayloadWriter : MemoryStream
    {
        private readonly Stream _innerStream;
        public bool LeaveInnerStreamOpen { get; }

        public PayloadWriter(Stream stream, bool leaveInnerStreamOpen)
        {
            _innerStream = stream;
            LeaveInnerStreamOpen = leaveInnerStreamOpen;
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
                byte[] payload = ms.ToArray();

                Random rnd = new Random();
                int paddingSize = rnd.Next(1, 129); // 1~128바이트 가변 패딩
                byte[] padding = new byte[paddingSize];
                rnd.NextBytes(padding);

                // [중요] 전체 본문 길이 = 패딩크기정보(1B) + 패딩데이터 + 실제데이터
                int totalBodyLength = 1 + paddingSize + payload.Length;

                // 1. 하부 엔진용 4바이트 헤더 기록 (전체 데이터 덩어리 크기)
                WriteInteger(totalBodyLength);

                // 2. 내부 구조 기록 (순서가 매우 중요함)
                _innerStream.WriteByte((byte)paddingSize); // 첫 바이트에 패딩 크기 기록
                _innerStream.Write(padding, 0, padding.Length); // 실제 패딩 데이터
                _innerStream.Write(payload, 0, payload.Length); // 진짜 메시지 본문

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
