# DLSAT

## TODO LIST FOR SSJ

- [x] 改helper，建全图；
- [ ] r2跟iblessing方法名字匹配；
- [x] 可以输入iblessing跳过分析；
- [x] 去掉不是cstr.开头的字符串；
- [ ] 整理helper的输出结果；

fuzz部分：

- [ ] openURL(url)；
- [ ] 把所有静态分析到的方法都hook一下(可能几百到一千?)，然后记录trace；
- [ ] 要有feedback吗？

## For Developer

<https://dwj1210.github.io/2020/08/06/%E5%88%A9%E7%94%A8%20URL%20Scheme%20%E8%BF%9C%E7%A8%8B%E7%AA%83%E5%8F%96%E7%94%A8%E6%88%B7%20token/>

### 飞书 URL Scheme

``` txt
lark://

// 唤起客户端
applink.feishu.cn/client/op/open

// 打开小程序
applink.feishu.cn/client/mini_program/open
示例：
applink.feishu.cn/client/mini_program/open?appId=1234567890&mode=window
applink.feishu.cn/client/mini_program/open?appId=1234567890&mode=window&path=pages%2fhome
applink.feishu.cn/client/mini_program/open?appId=1234567890&mode=window&path=pages%2fhome%3fxid%3d123
applink.feishu.cn/client/mini_program/open?appId=1234567890&mode=window&path=pages%2fhome%3fxid%3d123&path_pc=pages%2fpc_home%3fpid%3d123

// 打开聊天页面
applink.feishu.cn/client/chat/open
示例：
applink.feishu.cn/client/chat/open?openId=1234567890
applink.feishu.cn/client/chat/open?openChatId=oc_41e7bdf4877cfc316136f4ccf6c32613
applink.feishu.cn/client/chat/open?chatId=1234567890

// 打开一个已安装 H5 应用
applink.feishu.cn/client/web_app/open
示例：
applink.feishu.cn/client/web_app/open?appId=cli_xxxxxxxxxxxxxx&path=bytedance/d/home.htmld&mode=window
applink.feishu.cn/client/web_app/open?appId=xxx&path=/a/b&xxd=123
```

### 百度

var fuzzStrings = ["client/web?url=https://www.baidu.com",
    "web_?url=https://www.baidu.com",
    "jump?url=https://www.baidu.com",
    "to_web?title=POC&url=http://www.baidu.com",
    "dingtalkclient/action/open_platform_link?a=1&mobileLink=http://www.baidu.com",
    "easybrowse?openurl=http://www.baidu.com",
    "v1/easybrowse/open?url=http://www.baidu.com&style=menumode&newbrowser=1",
    "passenger/didi?url=https://www.baidu.com"
];

### 钉钉

``` xml
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/ding/home.html" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/ding/home.html" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/channel_detail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/channel_detail" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/channel_detail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/friendrequest" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/friendrequest" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/friendrequest" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/addContact" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/live_share_joinGroup" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/add_friend" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/add_friend" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/add_friend" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/joingrouprequest" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/joingrouprequest" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/ding/home.html" />
<data android:scheme="https" android:host="m.laiwang.com" android:path="/market/laiwang/dingding.php" />
<data android:scheme="http" android:host="m.laiwang.com" android:path="/market/laiwang/dingding.php" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/me_chat" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/me_chat" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/me_chat" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/conversation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/conversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/conversation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/conversation_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/conversation_setting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/conversation_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/office" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/office" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/office" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/enterprise/settings.html" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/enterprise/settings.html" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/enterprise/settings.html" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/org_microapp_list.html" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/org_microapp_list.html" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/org_microapp_list.html" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/joingroup" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/joingroup" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/joingroup" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/dingword" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/dingword" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/dingword" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/im/forward.html" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/im/forward.html" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/im/forward.html" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/im/send_auth.html" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/ding" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/ding" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/ding" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/meetingOrganizer" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/meetingOrganizer" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/meetingOrganizer" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/meetingAttendeesList" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/meetingAttendeesList" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/meetingAttendeesList" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/meetingCheckInDetail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/meetingCheckInDetail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/meetingCheckInDetail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dingSubTasksList" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dingSubTasksList" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dingSubTasksList" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/note" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/note" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/note" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/noteCreate" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/noteCreate" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/noteCreate" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/noteList" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/noteList" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/noteList" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/fileshelper" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/fileshelper" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/fileshelper" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dinglist" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dinglist" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dinglist" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dingcreate" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/ding/create_ding.html" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/ding/create_ding.html" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/ding/create_ding.html" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/ding_check_in" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/ding_check_in" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/ding_check_in" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dingsearch" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dingsearch" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dingsearch" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dingdeletelist" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dingdeletelist" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dingdeletelist" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dingcheckin" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dingcheckin" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dingcheckin" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/message_to_ding" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/message_to_ding" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/message_to_ding" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/focus_ding" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/focus_ding" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/focus_ding" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/link" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/link" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/link" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/openapp" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/openapp" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/openapp" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/creategroup" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/confenencelist" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/confenencelist" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/confenencelist" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/confenencelist" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/businessConference" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/businessConference" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/businessConference" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/businessConference" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/yunpan" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/yunpan" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/yunpan" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/sharespace" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/sharespace" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/sharespace" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/groupSpaceSetting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/my_connections" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/my_connections" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/my_connections" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/scan_bizcard" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/scan_bizcard" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/scan_bizcard" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/calendar" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/calendar" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/calendar" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/schedule_detail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/schedule_detail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/schedule_detail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/accountSafe" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/accountSafe" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/accountSafe" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/sharedcalendar" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/sharedcalendar" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/sharedcalendar" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/attendance" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/attendance" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/attendance" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/maillist" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/maillist" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/maillist" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/maillist" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/mailsignatureList" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/mailsignatureList" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/mailsignatureList" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/mailsignatureList" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dispatchorgmail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dispatchorgmail" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/dispatchorgmail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dispatchorgmail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/mailcompose" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/mailcompose" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/mailcompose" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/mailcompose" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/maildetail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/maildetail" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/maildetail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/maildetail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/mailconfig" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/mailconfig" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/mailconfig" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/new_mail_account" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/new_mail_account" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/new_mail_account" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/switchtab" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/switchtab" />
<data android:scheme="d" android:host="t" android:path="/a/switchtab" />
<data android:scheme="d" android:host="t" android:path="/p/link" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/profile" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/birth_setting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/robots_market" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/robots_finish" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/robots_setting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/bosslist" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_v1" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_v1" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_v1" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_v1_legacy" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_v1_legacy" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_v1_legacy" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_v2" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_v2" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_v2" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_v2_h5" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_v2_h5" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_v2_h5" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_v4" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_v4" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_v4" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/crmconversation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/crmconversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/crmconversation" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/crminfo" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/crminfo" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/crminfo" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/groupchat" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/groupchat" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/groupchat" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/manageorg" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/manageorg" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/manageorg" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/manageorg" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/orginvite" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/orginvite" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/orginvite" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/orginvite" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/attendanceDetail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/attendanceDetail" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/attendanceDetail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/attendanceDetail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/redpacketsDetail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/redpacketsDetail" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/redpacketsDetail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/redpacketsDetail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/crmCustomerList" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/crmCustomerList" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/action/crmCustomerList" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/crmFollowList" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/crmFollowList" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/action/crmFollowList" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dingxiaomi" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dingxiaomi" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/dingxiaomi" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/create_call_from_conversation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/create_call_from_conversation" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/create_call_from_conversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/login" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/oa_login" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/select_user" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/select_user" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/attendAssistant" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/attendAssistant" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/orgroot" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/orgroot" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/orgroot" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/safecenter" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/safecenter" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/safecenter" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/groupsetting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/groupsetting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/groupsetting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/managerRoleSetting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/managerRoleSetting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/managerRoleSetting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/userReport" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/userReport" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/userReport" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/extcontact" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/extcontact" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/extcontact" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/externalcontact" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/externalcontact" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/externalcontact" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/bussiness_contact_page" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/bussiness_contact_page" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/bussiness_contact_page" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/batchAddExtContacts" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/batchAddExtContacts" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/batchAddExtContacts" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/batchAddExtContacts" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/orginfo" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/orginfo" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/orginfo" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/devicebind" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/devicebind" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/devicebind" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/smartdevice" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/smartdevice" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/smartdevice" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/myRedenvelop" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/myRedenvelop" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/myRedenvelop" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dingtalk_id_settings" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dingtalk_id_settings" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/dingtalk_id_settings" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/orgapplylist" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/orgapplylist" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/orgapplylist" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/org_apply_setting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/org_apply_setting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/org_apply_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/visitor" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/visitor" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/visitor" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/messagejump" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/messagejump" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/action/messagejump" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_from_conversation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_from_conversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_from_conversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/search_enterprise_page" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/search_enterprise_page" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/search_enterprise_page" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/upgrade_inner_group" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/upgrade_inner_group" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/upgrade_inner_group" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/upgrade_cooperative_group" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/upgrade_cooperative_group" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/upgrade_cooperative_group" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/group_invite_qrcode" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/group_invite_qrcode" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/group_invite_qrcode" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/vpn_result" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/vpn_result" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/vpn_result" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/sendmsg" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/sendmsg" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/sendmsg" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/group_members" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/bindOrgMail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/bindOrgMail" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/bindOrgMail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/bindOrgMail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/mailguide" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/mailguide" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/mailguide" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/mailguide" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/jumprobot" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/jumprobot" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/jumprobot" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/orgCustomizeManage" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/orgCustomizeManage" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/orgCustomizeManage" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/myProfile" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/myProfile" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/myProfile" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/print_task_list" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/print_task_list" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/print_task_list" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/smartdevice_list" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/smartdevice_list" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/smartdevice_list" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/sendfriendrequest" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/sendfriendrequest" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/sendfriendrequest" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/live_select_conversation_and_open" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/live_select_conversation_and_open" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/live_select_conversation_and_open" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/member_messages" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/mail_settings_content_subscribe" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/mail_settings_content_subscribe" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/mail_settings_content_subscribe" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/mail_notification_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/mail_notification_setting" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/mail_notification_setting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/dt_mail_login" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/dt_mail_login" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/page/dt_mail_login" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/singleconversation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/singleconversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/singleconversation" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/change_ent_group" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/change_ent_group" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/change_ent_group" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/channelManagement" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/channelManagement" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/channelManagement" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/edit_employee" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/edit_employee" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/edit_employee" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/member_list_oa" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/member_list_oa" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/member_list_oa" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/im_campus_hr_conversations" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/im_campus_hr_conversations" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/im_campus_hr_conversations" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/im_campus_student_conversations" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/im_campus_student_conversations" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/im_campus_student_conversations" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/recruitment_resume_feed" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/recruitment_resume_feed" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/recruitment_resume_feed" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/recruitment_job_feed" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/recruitment_job_feed" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/recruitment_job_feed" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/recruitment_resume_info" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/recruitment_resume_info" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/recruitment_resume_info" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/recruitment_campus_company_home" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/recruitment_campus_company_home" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/recruitment_campus_company_home" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/secret_chat_list" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/secret_chat_list" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/secret_chat_list" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/open_micro_app" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/open_micro_app" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/open_micro_app" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/open_mini_app" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/open_mini_app" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/open_mini_app" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/org_cancel_disband" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/org_cancel_disband" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/org_cancel_disband" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/createorg_v4_add_member" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/createorg_v4_add_member" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/createorg_v4_add_member" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/neworginvite" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/neworginvite" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/neworginvite" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/organizationProfile" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/organizationProfile" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/organizationProfile" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/registerFinishedPage" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/registerFinishedPage" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/registerFinishedPage" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/privacy_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/privacy_setting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/privacy_setting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/exitOrganization" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/exitOrganization" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/exitOrganization" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/findMoreTeam" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/findMoreTeam" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/findMoreTeam" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/setBizCardAvatar" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/setBizCardAvatar" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/setBizCardAvatar" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/bizCardCircle" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/bizCardCircle" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/bizCardCircle" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/addBizCardFriend" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/addBizCardFriend" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/addBizCardFriend" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/myBizCardQrCode" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/myBizCardQrCode" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/myBizCardQrCode" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/localContact" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/localContact" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/localContact" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/friendRecommendation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/friendRecommendation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/friendRecommendation" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/facespace" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/facespace" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/facespace" />
<data android:scheme="scme201810106161885461dab4" android:host="dingtalkclient" android:path="/page/wallet" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/liveentrance" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/liveentrance" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/liveentrance" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/login_verify" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/login_verify" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/login_verify" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/connectionCircleHome" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/connectionCircleHome" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/connectionCircleHome" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/group_announcement" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/group_management" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/update_conv_title" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/add_group_member" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/attention_list" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/attention_list" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/attention_list" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/setpassword" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/setpassword" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/setpassword" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/add_sub_manager" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/add_sub_manager" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/add_sub_manager" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/org_logo_setting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/org_logo_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/org_logo_setting" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/oa_attend" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/oa_attend" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/oa_attend" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/oa_attendance" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/oa_attendance" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/oa_attendance" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/ding_pinned" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/ding_pinned" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/ding_pinned" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/live_playback_list" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/live_playback_list" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/live_playback_list" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/open_preview_combo_message" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/open_preview_combo_message" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/open_preview_combo_message" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/send_oriented_red_packets" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/send_oriented_red_packets" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/send_oriented_red_packets" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/join_conf" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/join_conf" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/join_conf" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/conf_detail" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/conf_detail" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/conf_detail" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/create_mcs_video_conf" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/create_mcs_video_conf" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/create_mcs_video_conf" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/create_mcs_audio_conf" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/create_mcs_audio_conf" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/create_mcs_audio_conf" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/create_mcs_video_talk" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/create_mcs_video_talk" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/create_mcs_video_talk" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/videoConfFromCalendar" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/robot_store" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/open_conversation" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/ownness_setting" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/chat_setting" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/open_platform_link" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/open_platform_link" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/open_platform_link" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/live/start.html" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/live/start.html" />
<data android:scheme="dingtalk" android:host="qr.dingtalk.com" android:path="/live/start.html" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/group_qrcode" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/group_qrcode" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/group_qrcode" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/action/chat_gif_input" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/action/chat_gif_input" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/action/chat_gif_input" />
<data android:scheme="https" android:host="qr.dingtalk.com" android:path="/page/set_group_bg" />
<data android:scheme="http" android:host="qr.dingtalk.com" android:path="/page/set_group_bg" />
<data android:scheme="dingtalk" android:host="dingtalkclient" android:path="/page/set_group_bg" />
```
