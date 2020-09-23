<?php

namespace yiiComponent\yiiLogin;

use Yii;
use yiiComponent\yiiLogin\models\Setting;
use yiiComponent\yiiLogin\models\User;
use yiiComponent\yiiLogin\models\UserOauth;
use linslin\yii2\curl\Curl;
use yiiComponent\yiiLogin\models\UserSafeLog;

/**
 * 用户创建表单
 *
 * Class UserCreateForm
 * @package app\forms
 */
class UserCreateForm extends \app\base\BaseModel
{
    /**
     * @var string $invite 邀请码
     */
    public $invite = null;

    /**
     * @var int $activityId 活动ID
     */
    public $activityId = 0;

    /**
     * @var int $activityMissionId 活动任务ID
     */
    public $activityMissionId = 0;

    /**
     * @var string $clientid 推送客户端ID
     */
    public $clientid;

    /**
     * @var string $username 用户名
     */
    public $username;

    /**
     * @var string $mobile 手机号码
     */
    public $mobile;

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
     * @var string $birthday 生日
     */
    public $birthday;

    /**
     * @var array $tags 标签
     */
    public $tags;

    /**
     * @var array $last_login_terminal 标签
     */
    public $last_login_terminal;

    /**
     * @var string $modelClass 模型类
     */
    public $modelClass;

    /**
     * @var string $data 数据
     */
    public $data;

    /**
     * @var int $type 类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台
     */
    public $type;

    /**
     * @var string $identity 身份信息
     */
    public $identity;

    /**
     * @var int $is_tester 是否测试员，0=>否，1=>是
     */
    public $is_tester;

    /**
     * @var string $last_login_version 最后登录版本
     */
    public $last_login_version;

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
     * @var string $_inviteModel 上级用户模型类
     */
    private $_inviteModel;


    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return array_merge(parent::rules(), [
            [['code', 'rawData', 'signature', 'encryptedData', 'iv'], 'safe'],

            [['mobile', 'modelClass'], 'required', 'on' => ['admin', 'user']],

            [['last_login_terminal', 'last_login_version'], 'required', 'on' => ['user']],

            [['mobile', 'modelClass', 'identity', 'data', 'type', 'last_login_terminal', 'sex', 'avatar', 'last_login_version'], 'required', 'on' => ['third-party']],

            [['invite', 'username', 'mobile', 'avatar', 'nickname', 'realname', 'birthday', 'clientid', 'last_login_version'], 'filter', 'filter' => 'trim'],

            [['sex', 'last_login_terminal', 'type', 'is_tester', 'activityId', 'activityMissionId'], 'integer', 'min' => 0],
            [['invite', 'username', 'mobile', 'avatar', 'nickname', 'realname', 'birthday', 'modelClass', 'clientid', 'last_login_version'], 'string'],
            ['type', 'in', 'range' => [1, 2, 3, 4, 5, 6]],
            ['is_tester', 'in', 'range' => [0, 1]],
            [['mobile'], 'match', 'pattern' => '/^1([3456789]{1})\d{9}$/'],

            [['invite'], 'validateInvite'],
            [['activityMissionId'], 'validateActivityMissionId'],
            ['type', 'validateType', 'on' => ['third-party']],
            ['iv', 'validateIv', 'on' => ['third-party']],
            ['identity', 'validateIdentity', 'on' => ['third-party']],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function scenarios()
    {
        return array_merge(parent::scenarios(), [
            'admin' => ['mobile', 'modelClass', 'username', 'avatar', 'nickname', 'birthday', 'sex', 'is_tester'],
            'user' => ['invite', 'mobile', 'modelClass', 'last_login_terminal', 'clientid', 'last_login_version'],
            'third-party' => [
                'mobile', 'modelClass', 'last_login_terminal', 'avatar', 'nickname', 'realname', 'sex', 'data', 'type',
                'identity', 'clientid', 'last_login_version', 'code', 'rawData', 'signature', 'encryptedData', 'iv',
            ],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function attributes()
    {
        return [
            'clientid' => Yii::t('app', '推送客户端ID'),
            'username' => Yii::t('app', '用户名'),
            'mobile' => Yii::t('app', '手机号码'),
            'avatar' => Yii::t('app', '头像'),
            'nickname' => Yii::t('app', '昵称'),
            'realname' => Yii::t('app', '真实姓名'),
            'sex' => Yii::t('app', '性别，0=>未知，1=>男，2=>女'),
            'birthday' => Yii::t('app', '生日'),
            'tags' => Yii::t('app', '标签（json）'),
            'modelClass' => Yii::t('app', '模型类'),
            'data' => Yii::t('app', '数据（json）'),
            'identity' => Yii::t('app', '身份信息'),
            'type' => Yii::t('app', '类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台'),
            'invite' => Yii::t('app', '邀请码'),
            'is_tester' => Yii::t('app', '是否测试员，0=>否，1=>是'),
            'last_login_version' => Yii::t('app', '最后登录版本号'),
            'last_login_terminal' => Yii::t('app', '最后登录终端'),
            'activityId' => Yii::t('app', '活动ID'),
            'activityMissionId' => Yii::t('app', '活动任务ID'),
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
     * @param  array $params 规则中给出的其他键值对
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
     * @param  array $params 规则中给出的其他键值对
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
     * 验证邀请码
     *
     * @param  string $attribute 当前正在验证的属性
     * @param  array $params 规则中给出的其他键值对
     * @return bool|string
     */
    public function validateInvite($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if (!$this->inviteModel) {
                $this->addError($attribute, Yii::t('app/error', '{attribute} is invalid.', ['attribute' => $attribute]));
            }
        }
    }

    /**
     * 提交
     *
     * @return bool|mixed
     * @throws \Throwable
     */
    public function submit()
    {
        if (!$this->validate()) {
            return $this->errors;
        }

        return Yii::$app->db->transaction(function ($e) {
            // 创建用户
            $user = $this->_create();

            if ($user) {
                // 创建用户授权
                if ($this->scenario == 'third-party') {
                    $this->_createUserOauth($user);
                }

                // 创建行为日志
                if ($this->scenario == 'user') {
                    $this->_createUserBehaviorLog($user);
                }

                // TODO: 管理员行为日志
                if ($this->scenario == 'admin') {
                    // $this->_createAdminBehaviorLog();
                }
            }

            if (!$this->hasErrors()) {
                return $user;
            } else {
                $e->transaction->rollBack();
                return $this->errors;
            }
        });
    }


    /* ----private---- */

    /**
     * 获取上级用户模型
     *
     * @protected
     * @return array|null|string|\yii\db\ActiveRecord
     */
    protected function getInviteModel()
    {
        // 有邀请码获取模型
        if ($this->invite) {
            if (!$this->_inviteModel) {
                $modelClass = $this->modelClass;
                $this->_inviteModel = $modelClass::find()->where(['id' => base64_decode(urldecode($this->invite))])->limit(1)->one();
            }

            return $this->_inviteModel;
        }

        // 没有邀请码直接返回false
        return false;
    }

    /**
     * 创建用户
     *
     * @private
     * @return User|bool
     * @throws \yii\base\Exception
     */
    private function _create()
    {
        $modelClass = $this->modelClass;

        $model = new $modelClass;
        $data = [
            'username' => $this->username ? $this->username : 'u' . $this->mobile, // ?? 判断空字符串为真 ''
            'mobile' => $this->mobile,
            'nickname' => $this->nickname ? $this->nickname : (
                $this->realname ? $this->realname : '用户' . ((int)substr($this->mobile, -6, 6) + (int)rand(12345, 54321))
            ),
            'sex' => $this->sex,
            'avatar' => $this->avatar,
            'birthday' => $this->birthday,
            'tags' => $this->tags ? json_encode($this->tags) : '[]',
        ];
        $model->setPassword($modelClass::DEFAULT_PASSWORD);

        if ($this->scenario == 'admin') {
            $data['is_tester'] = $this->is_tester;
        }

        if ($this->scenario == 'user' || $this->scenario == 'third-party') {
            $model->generateAuthKey();
            $data['last_login_at'] = date('Y-m-d H:i:s');
            $data['last_login_ip'] = Yii::$app->request->userIP;
            $data['last_login_terminal'] = $this->last_login_terminal;
            $data['clientid'] = $this->clientid;
            $data['last_login_version'] = $this->last_login_version;
        }

        $model->load($data, '');

        if (!$model->save()) {
            $this->addErrors($model->errors);
            return false;
        }

        // 重新查出获取创建时的默认值
        $model = $modelClass::findOne($model->id);

        return $model;
    }

    /**
     * 创建用户行为日志
     *
     * @private
     * @param  object $user 用户模型对象
     * @return void
     */
    private function _createUserBehaviorLog($user)
    {
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

    /**
     * 创建用户授权
     *
     * @private
     * @param  object $user 用户模型对象
     * @return UserOauth|bool
     */
    private function _createUserOauth($user)
    {
        $model = new UserOauth;
        $model->load([
            'user_id' => $user->id,
            'type' => $this->type,
            'identity' => $this->identity,
            'data' => json_encode($this->data),
        ], '');

        if (!$model->save()) {
            $this->addErrors($model->errors);
            return false;
        }

        return $model;
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
     * @param  string $sessionKey     私钥
     * @param  string $encryptedData  加密的用户数据
     * @param  string $iv            与用户数据一同返回的初始向量
     * @param  string $data          解密后的原文
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
