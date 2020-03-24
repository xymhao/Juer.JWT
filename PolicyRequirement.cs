using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace Juer.JWT
{
    public class PolicyRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// �û�Ȩ�޼���
        /// </summary>
        public List<UserPermission> UserPermissions { get; private set; }
        /// <summary>
        /// ��Ȩ��action
        /// </summary>
        public string DeniedAction { get; set; }
        /// <summary>
        /// ����
        /// </summary>
        public PolicyRequirement()
        {
            //û��Ȩ������ת�����·��
            DeniedAction = new PathString("/api/nopermission");
            //�û���Ȩ�޷��ʵ�·������,��Ȼ���Դ����ݿ��ȡ
            UserPermissions = new List<UserPermission> {
                new UserPermission {  Url="/api/value3", UserName="admin"},
            };
        }
    }

    /// <summary>
    /// �û�Ȩ�޳���ʵ��
    /// </summary>
    public class UserPermission
    {
        /// <summary>
        /// �û���
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// ����Url
        /// </summary>
        public string Url { get; set; }
    }
}