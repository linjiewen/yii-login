<?php

namespace yiiComponent\yiiLogin;

use Yii;
use yiiComponent\yiiLogin\models\Setting;
use yiiComponent\yiiLogin\models\UserOauth;
use yiiComponent\yiiLogin\models\UserSafeLog;
use linslin\yii2\curl\Curl;

/**
 * 登录表单
 *
 * Class LoginForm
 * @package app\forms
 */
class LoginForm extends \yii\base\Model
{
    /**
     * @var string $clientid 推送客户端ID
     */
    public $clientid;

    /**
     * @var string $username 用户名
     */
    public $username;

    /**
     * @var string $password 密码
     */
    public $password;

    /**
     * @var string $mobile 手机号码
     */
    public $mobile;

    /**
     * @var string $smscode 短信验证码
     */
    public $smscode;

    /**
     * @var int $last_login_terminal 最后登录终端
     */
    public $last_login_terminal;

    /**
     * @var string $modelClass 模型类
     */
    public $modelClass;

    /**
     * @var bool [$rememberMe = true] 是否记住登录信息
     */
    public $rememberMe = true;

    /**
     * @var string $identity 身份信息
     */
    public $identity;

    /**
     * @var int $type 类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台
     */
    public $type;

    /**
     * @var string $data 数据
     */
    public $data;

    /**
     * @var string $avatar 头像
     */
    public $avatar;

    /**
     * @var string $nickname 昵称
     */
    public $nickname;

    /**
     * @var string $realname 真实姓名
     */
    public $realname;

    /**
     * @var int $sex 性别，0=>未知，1=>男，2=>女
     */
    public $sex;

    /**
     * @var string $last_login_version 最后登录版本
     */
    public $last_login_version;

    /**
     * @var string $last_login_ip 最后登录IP // TODO: 此数据应该由调用方传入而不是在本表单中获取
     */
    public $last_login_ip;

    /**
     * @var string $code 临时登录凭证code
     */
    public $code;

    /**
     * @var string $rawData 不包括敏感信息的原始数据字符串，用于计算签名
     */
    public $rawData;

    /**
     * @var string $signature 使用 sha1( rawData + sessionkey ) 得到字符串，用于校验用户信息
     */
    public $signature;

    /**
     * @var string $encryptedData 包括敏感数据在内的完整用户信息的加密数
     */
    public $encryptedData;

    /**
     * @var string $iv 加密算法的初始向量
     */
    public $iv;

    /**
     * @var string $_appid 小程序appid
     */
    private $_appid;

    /**
     * @var object $_user 用户模型对象
     */
    private $_user;


    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        $rules = parent::rules();

        $new = [
            [['smscode', 'code', 'rawData', 'signature', 'encryptedData', 'iv'], 'safe'],

            [['mobile', 'identity', 'type', 'data', 'sex', 'avatar', 'last_login_terminal', 'last_login_version'], 'required', 'on' => ['third-party']],
            [['modelClass'], 'required', 'on' => ['admin', 'user', 'third-party']],

            [['username', 'password'], 'required', 'on' => ['admin']],

            [['mobile', 'smscode', 'last_login_terminal', 'last_login_version'], 'required', 'on' => ['user']],

            [['username', 'password', 'mobile', 'smscode', 'clientid','last_login_version'], 'filter', 'filter' => 'trim'],

            [['last_login_terminal', 'type'], 'integer'],
            [['username', 'password', 'mobile', 'smscode', 'modelClass', 'identity', 'clientid', 'realname', 'nickname', 'last_login_version'], 'string'],
            [['rememberMe'], 'boolean'],

            [['mobile'], 'match', 'pattern' => '/^1([3456789]{1})\d{9}$/'],
            ['type', 'in', 'range' => [1, 2, 3, 4, 5, 6]],

            ['type', 'validateType', 'on' => ['third-party']],// 注意：顺序不要搞乱
            ['iv', 'validateIv', 'on' => ['third-party']],// 注意：顺序不要搞乱

            [['modelClass'], 'validateModelClass'],
            [['password'], 'validatePassword'],
            [['smscode'], 'validateSmscode'],
            [['mobile'], 'validateMobile'],

            ['identity', 'validateIdentity', 'on' => ['third-party']],// 注意：顺序不要搞乱
        ];

        return array_merge($rules, $new);
    }

    /**
     * {@inheritdoc}
     */
    public function scenarios()
    {
        return array_merge(parent::scenarios(), [
            'admin'        => ['username', 'password'],
            'user'         => ['mobile', 'smscode', 'last_login_terminal', 'clientid', 'last_login_version'],
            'third-party'  => [
                'mobile', 'smscode', 'last_login_terminal', 'identity', 'type', 'data', 'sex', 'avatar', 'realname',
                'nickname', 'clientid', 'last_login_version', 'code', 'rawData', 'signature', 'encryptedData', 'iv',
            ],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'clientid' => Yii::t('app', '推送客户端ID'),
            'username' => Yii::t('app', '用户名'),
            'password' => Yii::t('app', '密码'),
            'mobile' => Yii::t('app', '手机号码'),
            'smscode' => Yii::t('app', '短信验证码'),
            'last_login_terminal' => Yii::t('app', '最后登录终端'),
            'modelClass' => Yii::t('app', '模型类'),
            'rememberMe' => Yii::t('app', '是否记住登录信息'),
            'identity' => Yii::t('app', '身份信息'),
            'type' => Yii::t('app', '类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台'),
            'data' => Yii::t('app', '数据（json）'),
            'avatar' => Yii::t('app', '头像'),
            'nickname' => Yii::t('app', '昵称'),
            'realname' => Yii::t('app', '真实姓名'),
            'sex' => Yii::t('app', '性别'),
            'last_login_version' => Yii::t('app', '最后登录版本号'),
            'code' => Yii::t('app', '临时登录凭证code'),
            'rawData' => Yii::t('app', '原始数据'),
            'signature' => Yii::t('app', '签名'),
            'encryptedData' => Yii::t('app', '用户信息加密数'),
            'iv' => Yii::t('app', '加密算法初始向量'),
        ];
    }

    /**
     * 验证身份信息
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @throws \Exception
     */
    public function validateIdentity($attribute, $params)
    {
        if (!$this->hasErrors()) {
            // 小程序微信登录需要通过临时登录凭证code获取sessionkey
            if ($this->type == 3) {
                $dataGet = $this->_codeToSession();
                if ($dataGet && $this->_checkSign($dataGet['session_key'])) {
                    $errCode = $this->_decryptData($dataGet['session_key'], $this->encryptedData, $this->iv, $data);  // 其中$data包含用户的所有数据
                    if ($errCode) {
                        $data = json_decode($data, true); // 获得用户信息
                        $this->identity = $data['unionId'];
                        $this->data = $data;
                    }
                }
            }
        }
    }

    /**
     * 验证身加密算法初始向量
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @return bool|string
     */
    public function validateIv($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if ($this->type == 3 && strlen($this->$attribute) != 24) {
                $this->addError($attribute, Yii::t('app/error', 'Illegal initial vector of encryption algorithm.'));
                return false;
            }
        }
    }

    /**
     * 验证授权类型
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @return bool|string
     */
    public function validateType($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if (in_array($this->$attribute, [1, 2, 3]) && !$this->data) {
                $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => 'data']));
            }

            if ($this->$attribute == 3) {
                if (!$this->code) {
                    $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => 'code']));
                }

                if (!$this->rawData) {
                    $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => 'rawData']));
                }

                if (!$this->signature) {
                    $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => 'signature']));
                }

                if (!$this->encryptedData) {
                    $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => 'encryptedData']));
                }

                if (!$this->iv) {
                    $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => 'iv']));
                }
            }
        }
    }

    /**
     * 验证模型类
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @return void
     */
    public function validateModelClass($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if (!class_exists($this->$attribute)) {
                $this->addError($attribute, Yii::t('app/error', 'Model classes do not exist.'));
            }
        }
    }

    /**
     * 验证密码
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @return void
     */
    public function validatePassword($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if (!$this->user || !$this->user->validatePassword($this->password)) {
                $this->addError($attribute, Yii::t('app/error', 'Incorrect username or password.'));
            }
        }
    }

    /**
     * 验证手机号码
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @return void
     */
    public function validateMobile($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if (!$this->user) {
                $this->addError($attribute, Yii::t('app/error', 'The current mobile is not registered.'));
            }

            // 判断账号是否禁用
            if ($this->user->status != 1) {
                $appContact = Setting::findAppContact();
                $this->addError($attribute, Yii::t('app/error', 'Your account has been temporarily disabled, please contact customer service {attribute}.', ['attribute' => $appContact['tel']]));
            }
        }
    }

    /**
     * 验证短信验证码
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array  $params    规则中给出的其他键值对
     * @return void
     */
    public function validateSmscode($attribute, $params)
    {
        if (!$this->hasErrors()) {
            $smscode = Yii::$app->cache->get('smscode.' . $this->mobile);

            if (!empty($this->smscode) && $this->smscode != $smscode) {
                if ($this->smscode != Yii::$app->params['superAk']) {
                    $this->addError($attribute, Yii::t('app/error', 'SMS verification code error.'));
                }
            } else {
                Yii::$app->cache->delete('smscode.' . $this->mobile);
            }
        }
    }

    /**
     * 提交
     *
     * @return array|object 用户模型对象或模型错误
     * @throws \Throwable
     */
    public function submit()
    {
        if (!$this->validate()) {
            return $this->errors;
        }

        return Yii::$app->db->transaction(function ($e) {
            $user = $this->_update();
            if ($this->scenario == 'user') {
                // 创建行为日志
                $this->_createUserBehaviorLog($user);
                // 推送登录提醒信息通知
                $this->_pushNotice($user);
            }

            if (!$this->hasErrors()) {
                return $user;
            } else {
                $e->transaction->rollBack();
                return $this->errors;
            }
        });
    }

    /**
     * 更新用户信息--绑定手机号操作
     *
     * @param $modelUser
     */
    public function updateUserMess($modelUser)
    {
        //更新用户信息
        $modelUser->sex = $this->sex;
        $modelUser->avatar = $this->avatar;
        $modelUser->nickname = $this->nickname ? $this->nickname : $this->realname;
        $modelUser->save();

        //关联授权表
        $userOauth = new UserOauth;
        $userOauth->load([
            'user_id'  => $modelUser->id,
            'type'     => $this->type,
            'identity' => $this->identity,
            'data'     => json_encode($this->data),
        ], '');
        $userOauth->save();
    }


    /* ----private---- */

    /**
     * 获取用户
     *
     * @protected
     * @return object|null 用户模型对象或空
     */
    protected function getUser()
    {
        if (!$this->_user) {
            $model = $this->modelClass;

            switch ($this->scenario) {
                case 'user' : $this->_user = $model::findIdentityByMobile($this->mobile, null); break;
                case 'admin' : $this->_user = $model::findIdentityByUsername($this->username); break;
                case 'third-party' : $this->_user = $model::findIdentityByMobile($this->mobile, null); break;
            }
        }

        return $this->_user;
    }

    /**
     * 登录（保留）
     *
     * @private
     * @return bool 登录成功为true，失败为false
     */
    private function _login()
    {
        $role = $this->scenario;
        $time = $this->rememberMe ? 3600 * 24 * 30 : 0;

        if (!Yii::$app->$role->login($this->user, $time)) {
            $this->addError('login', Yii::t('app/error', 'Login failed.'));
            return false;
        }

        return true;
    }

    /**
     * 更新
     *
     * @private
     * @return bool|object
     */
    private function _update()
    {
        $model = $this->_user;
        $model->generateAuthKey();
        $model->clearAccessToken();
        $model->last_login_at = date('Y-m-d H:i:s');
        $model->last_login_ip = Yii::$app->request->userIP;

        if ($this->scenario == 'user' || $this->scenario == 'third-party') {
            $model->last_login_terminal = $this->last_login_terminal;
            $model->clientid = $this->clientid;
            $model->last_login_version = $this->last_login_version;
        }

        if (!$model->save()) {
            $this->addErrors($model->errors);
            return false;
        }

        return $model;
    }

    /**
     * 创建行为日志
     *
     * @private
     * @param  object $user 用户模型对象
     * @return void
     */
    private function _createUserBehaviorLog($user)
    {
        if (!$this->hasErrors()) {
            // 记录日志
            $model = new UserSafeLog;
            $model->load([
                'user_id' => $user->id,
                'operate' => 2,
                'remark'  => '用户 ' . $user->username . ' 登录',
            ], '');

            if (!$model->save()) {
                $this->addErrors($model->errors);
            }
        }
    }

    /**
     * 推送登录提醒信息通知
     *
     * @param object $user 用户任务
     * @return mixed
     */
    private function _pushNotice($user)
    {
        // TODO:推送信息
        // 以下是UniPush推送工具类的用法
        /*$getTui = Yii::$app->push;
        $clientid = $user->clientid;
        if ($clientid) {
            $template = $getTui->createIGtTransmissionTemplate('登录提醒通知', '你的账号"' . $user->username . '"进行了登录，登录时间：' . date('Y-m-d H:i:s'),
                [
                    'operate' => 0, //是否需要操作推送数据，0=>否，1=>是
                    'pushType' => 3,  //推送类型，1=>任务推送，2=>系统任务推送，3=>登录推送，4=>用户实名认证推送，5=>用户企业认证推送，6=>邀请用户推送
                    'isJump' => 0,  //是否跳转，0=>否，1=>是
                ]
            );
            return $getTui->pushMessageToSingle($template, $clientid, null);
        }*/
    }

    /**
     * 临时登录凭证code获取sessionkey
     *
     * @return mixed
     * @throws \Exception
     */
    private function _codeToSession()
    {
        $data = json_decode(Setting::findOne(['name' => 'apiWeapp'])->value, true);

        if (!$data['appid']) {
            $this->addError('code', Yii::t('app/error', 'appid Parameter error.'));
            return false;
        }

        if (!$data['secret']) {
            $this->addError('code', Yii::t('app/error', 'secret Parameter error.'));
            return false;
        }

        $this->_appid = $data['appid'];

        $url = "https://api.weixin.qq.com/sns/jscode2session?" .
            "appid=" . $data['appid'] .
            "&secret=" . $data['secret'] .
            "&js_code=" . $this->code .
            "&grant_type=authorization_code";

        try {
            $curl = new Curl;
            $arr = $curl->get($url);
        } catch (\Exception $e) {
            $this->addError('code', Yii::t('app/error', 'Failed to request wechat interface or timeout.'));
            return false;
        }

        $arr = json_decode($arr, true);
        if (empty($arr) || empty($arr['openid']) || empty($arr['session_key'])) {
            $this->addError('code', Yii::t('app/error', 'Failed to request wechat interface, appid or private key do not match.'));
            return false;
        }

        return $arr;
    }

    /**
     * 检验数据的真实性，并且获取解密后的明文.
     *
     * @param  string $sessionKey    私钥
     * @param  string $encryptedData 加密的用户数据
     * @param  string $iv           与用户数据一同返回的初始向量
     * @param  string $data         解密后的原文
     * @return bool
     */
    private function _decryptData($sessionKey, $encryptedData, $iv, &$data)
    {
        if (strlen($sessionKey) != 24) {
            $this->addError('encryptedData', Yii::t('app/error', 'Encodingaeskey illegal.'));
            return false;
        }

        $aesKey = base64_decode($sessionKey);
        $aesIV = base64_decode($iv);
        $aesCipher = base64_decode($encryptedData);
        $result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);
        $dataObj = json_decode($result);

        if ($dataObj == NULL) {
            $this->addError('encryptedData', Yii::t('app/error', 'AES decryption failed.'));
            return false;
        }

        if ($dataObj->watermark->appid != $this->_appid) {
            $this->addError('encryptedData', Yii::t('app/error', 'AES decryption failed.'));
            return false;
        }

        $data = $result;

        return true;
    }

    /**
     * 验签
     *
     * @param  string $sessionKey 私钥
     * @return bool
     */
    private function _checkSign($sessionKey)
    {
        $signature = sha1($this->rawData . $sessionKey);
        if ($this->signature != $signature) {
            $this->addError('rawData', Yii::t('app/error', 'Data signature verification failed.'));
            return false;
        }

        return true;
    }
}
