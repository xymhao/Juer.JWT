namespace Juer.JWT
{
    public static class Const
    {
        /// <summary>
        /// ����Ϊ����ʾ��д��һ����Կ��ʵ�������������Դ������ļ���ȡ,����������Ϲ���������ɵ�һ����Կ
        /// </summary>
        public const string SecurityKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI2a2EJ7m872v0afyoSDJT2o1+SitIeJSWtLJU8/Wz2m7gStexajkeD+Lka6DSTy8gt9UwfgVQo6uKjVLG5Ex7PiGOODVqAEghBuS7JzIYU5RvI543nNDAPfnJsas96mSA7L/mD7RTE2drj6hf3oZjJpMPZUQI/B1Qjb5H3K3PNwIDAQAB";
        /// <summary>
        /// վ���ַ
        /// </summary>
        public const string Domain = "http://localhost:5001";

        /// <summary>
        /// �����ˣ�֮����Ū�ɿɱ����Ϊ���ýӿڶ�̬�������ֵ��ģ��ǿ��TokenʧЧ
        /// ��ʵҵ�񳡾����������ݿ����redis��һ�����û�id��ص�ֵ������token����֤token��ʱ���ȡ���־û���ֵȥУ��
        /// ������µ�½����ˢ�����ֵ
        /// </summary>
        public static string ValidAudience;
    }
}