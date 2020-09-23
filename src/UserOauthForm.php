<?php

namespace yiiComponent\yiiLogin;

use Yii;
use yiiComponent\yiiLogin\models\User;
use yiiComponent\yiiLogin\models\Setting;
use yiiComponent\yiiLogin\models\UserOauth;
use yiiComponent\yiiLogin\models\UserSafeLog;
use linslin\yii2\curl\Curl;

/**
 * 用户授权登录表单
 *
 * Class UserOauthForm
 * @package app\forms
 */
class UserOauthForm extends \app\base\BaseModel
{
    /**
     * @var int $type 类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台
     */
    public $type;

    /**
     * @var string $identity 身份信息
     */
    public $identity;

    /**
     * @var int $last_login_terminal 最后登录终端
     */
    public $last_login_terminal;

    /**
     * @var string $clientid 推送客户端ID
     */
    public $clientid;

    /**
     * @var string $data 数据
     */
    public $data;

    /**
     * @var string $avatar 头像
     */
    public $avatar;

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
     * {@inheritdoc}
     */
    public function rules()
    {
        return array_merge(parent::rules(), [
            [['data', 'code', 'rawData', 'signature', 'encryptedData', 'iv'], 'safe'],
            [['type', 'identity', 'last_login_terminal'], 'required'],

            [['identity', 'clientid', 'last_login_version'], 'filter', 'filter' => 'trim'],
            [['identity', 'clientid', 'last_login_version'], 'string'],

            ['type', 'in', 'range' => [1, 2, 3, 4, 5, 6]],

            ['type', 'validateType'],
            ['iv', 'validateIv'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'type' => Yii::t('app', '类型'),
            'identity' => Yii::t('app', '身份信息'),
            'last_login_terminal' => Yii::t('app', '最后登录终端'),
            'clientid' => Yii::t('app', '推送客户端ID'),
            'data' => Yii::t('app', '数据（json）'),
            'avatar' => Yii::t('app', '头像'),
            'realname' => Yii::t('app', '真实姓名'),
            'sex' => Yii::t('app', '性别'),
            'last_login_version' => Yii::t('app', '最后登录版本'),
            'code' => Yii::t('app', '临时登录凭证code'),
            'rawData' => Yii::t('app', '原始数据'),
            'signature' => Yii::t('app', '签名'),
            'encryptedData' => Yii::t('app', '用户信息加密数'),
            'iv' => Yii::t('app', '加密算法初始向量'),
        ];
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
     * 提交
     *
     * @return array|mixed
     * @throws \Throwable
     */
    public function submit()
    {
        if (!$this->validate()) {
            return $this->errors;
        }

        return Yii::$app->db->transaction(function ($e) {
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

            if (!$this->hasErrors()) {
                $user = $this->_getUserMess();
                // 创建行为日志
                $this->_createUserBehaviorLog($user);
                return $user;
            } else {
                $e->transaction->rollBack();
                return $this->errors;
            }
        });
    }


    /* ----private---- */

    /**
     * 获取用户信息
     *
     * @return User|array|bool|null
     * @throws \yii\base\Exception
     */
    private function _getUserMess()
    {
        $userOauth = UserOauth::find()->select(['user_id'])
            ->where([
                'type' => $this->type,
                'identity' => $this->identity,
                'is_trash' => 0,
                'status' => 1
            ])->one();

        // 如果不存在授权关联
        if (!$userOauth) {
            // 如果是微信授权
            if (in_array($this->type, [1, 2, 3])) {
                // 通过unionId获取用户授权信息
                $commonUserOauth = UserOauth::find()
                    ->where([
                        'type' => [1, 2, 3],
                        'identity' => $this->identity,
                        'is_trash' => 0,
                        'status' => 1
                    ])->one();

                // 如果存在有共同的unionId
                if ($commonUserOauth) {
                    // 创建授权关联
                    $oauthModel = $this->_createUserOauth($commonUserOauth->user);
                    if ($oauthModel) {
                        $userId = $oauthModel['user_id'];
                    } else {
                        return false;
                    }

                } else {
                    $this->addError('identity', Yii::t('app/error', 'Object not found.'));
                    return false;
                }
            } else {
                $this->addError('identity', Yii::t('app/error', 'Object not found.'));
                return false;
            }
        } else {
            $userId = $userOauth['user_id'];
        }

        $model = $this->_update($userId);

        return $model;
    }

    /**
     * 更新
     *
     * @private
     * @param $userId
     * @return User|array|bool|null
     * @throws \yii\base\Exception
     */
    private function _update($userId)
    {
        $model = User::find()->where(['id' => $userId, 'is_trash' => 0, 'status' => 1])->one();
        $model->generateAuthKey();
        $model->clearAccessToken();
        $model->last_login_at = date('Y-m-d H:i:s');
        $model->last_login_ip = Yii::$app->request->userIP;
        $model->last_login_terminal = $this->last_login_terminal;
        $model->clientid = $this->clientid;
        $model->last_login_version = $this->last_login_version;

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
            'user_id'  => $user->id,
            'type'     => $this->type,
            'identity' => $this->identity,
            'data'     => json_encode($this->data),
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

        Yii::$app->cache->set('session_key' . '-' . $this->code, $arr['session_key']);

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
     * @param string $sessionKey 私钥
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
