<?php

namespace yiiComponent\yiiLogin\models;

use Yii;

/**
 * This is the model class for table "{{%user}}".
 *
 * @property string $id
 * @property string $clientid 客户端ID
 * @property string $username 用户名
 * @property string $password_hash 加密密码
 * @property string $password_reset_token 重置密码令牌
 * @property string $auth_key 认证密钥
 * @property string $access_token 访问令牌
 * @property string $mobile 手机号码
 * @property string $avatar 头像
 * @property string $nickname 昵称
 * @property string $realname 真实姓名
 * @property int $sex 性别，0=>未知，1=>男，2=>女
 * @property string $birthday 生日
 * @property string $tags 标签（json）
 * @property int $is_tester 是否测试员，0=>否，1=>是
 * @property int $is_trash 是否删除，0=>否，1=>是
 * @property int $status 状态，0=>禁用，1=>启用
 * @property string $created_at 创建时间
 * @property string $updated_at 更新时间
 * @property string $deleted_at 删除时间
 * @property string $last_login_at 最后登录时间
 * @property string $last_login_ip 最后登录IP
 * @property int $last_login_terminal 最后登录终端
 * @property string $last_login_version 最后登录版本
 * @property string $allowance 请求剩余次数
 * @property string $allowance_updated_at 请求更新时间
 *
 * @property UserOauth[] $userOauths
 * @property UserSafeLog[] $userSafeLogs
 */
class User extends \yiiComponent\yiiLogin\models\BaseIdentityActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return '{{%user}}';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['id', 'sex', 'is_tester', 'is_trash', 'status', 'last_login_terminal', 'allowance', 'allowance_updated_at'], 'integer', 'min' => 0],
            [['birthday'], 'string'],
            [['clientid', 'password_reset_token', 'auth_key', 'access_token'], 'string', 'max' => 64],
            [['username', 'mobile', 'nickname', 'realname', 'last_login_ip', 'last_login_version'], 'string', 'max' => 16],
            [['password_hash', 'avatar', 'tags'], 'string', 'max' => 255],

            [['created_at', 'updated_at', 'deleted_at', 'last_login_at'], 'datetime', 'format' => 'yyyy-MM-dd HH:mm:ss'],

            [['clientid', 'password_reset_token', 'auth_key', 'access_token', 'mobile', 'deleted_at', 'last_login_at'], 'default', 'value' => null],
            [['username', 'password_hash', 'avatar', 'nickname', 'realname', 'birthday', 'tags', 'last_login_ip', 'last_login_version'], 'default', 'value' => ''],
            [['sex', 'is_tester', 'is_trash', 'last_login_terminal', 'allowance', 'allowance_updated_at'], 'default', 'value' => 0],
            [['status'], 'default', 'value' => 1],

            [['username'], 'unique'],
            [['auth_key'], 'unique'],
            [['mobile'], 'unique'],
            [['password_reset_token'], 'unique'],
            [['access_token'], 'unique'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => Yii::t('app', 'ID'),
            'clientid' => Yii::t('app', '客户端ID'),
            'username' => Yii::t('app', '用户名'),
            'password_hash' => Yii::t('app', '加密密码'),
            'password_reset_token' => Yii::t('app', '重置密码令牌'),
            'auth_key' => Yii::t('app', '认证密钥'),
            'access_token' => Yii::t('app', '访问令牌'),
            'mobile' => Yii::t('app', '手机号码'),
            'avatar' => Yii::t('app', '头像'),
            'nickname' => Yii::t('app', '昵称'),
            'realname' => Yii::t('app', '真实姓名'),
            'sex' => Yii::t('app', '性别，0=>未知，1=>男，2=>女'),
            'birthday' => Yii::t('app', '生日'),
            'tags' => Yii::t('app', '标签（json）'),
            'is_tester' => Yii::t('app', '是否测试员，0=>否，1=>是'),
            'is_trash' => Yii::t('app', '是否删除，0=>否，1=>是'),
            'status' => Yii::t('app', '状态，0=>禁用，1=>启用'),
            'created_at' => Yii::t('app', '创建时间'),
            'updated_at' => Yii::t('app', '更新时间'),
            'deleted_at' => Yii::t('app', '删除时间'),
            'last_login_at' => Yii::t('app', '最后登录时间'),
            'last_login_ip' => Yii::t('app', '最后登录IP'),
            'last_login_terminal' => Yii::t('app', '最后登录终端'),
            'last_login_version' => Yii::t('app', '最后登录版本'),
            'allowance' => Yii::t('app', '请求剩余次数'),
            'allowance_updated_at' => Yii::t('app', '请求更新时间'),
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getUserOauths()
    {
        return $this->hasMany(UserOauth::className(), ['user_id' => 'id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getUserSafeLogs()
    {
        return $this->hasMany(UserSafeLog::className(), ['user_id' => 'id']);
    }
}
