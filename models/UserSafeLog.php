<?php

namespace yiiComponent\yiiLogin\models;

use Yii;

/**
 * This is the model class for table "{{%user_safe_log}}".
 *
 * @property string $id
 * @property string $user_id 用户ID
 * @property int $operate 操作，1=>注册，2=>登录，3=>更新个人信息，4=>修改密码，5=>修改手机号码，6=>管理员创建
 * @property string $remark 备注
 * @property int $is_trash 是否删除，0=>否，1=>是
 * @property int $status 状态，0=>禁用，1=>启用
 * @property string $created_at 创建时间
 * @property string $updated_at 更新时间
 * @property string $deleted_at 删除时间
 *
 * @property User $user
 */
class UserSafeLog extends \yiiComponent\yiiLogin\models\BaseActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return '{{%user_safe_log}}';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['id', 'user_id', 'operate', 'is_trash', 'status'], 'integer', 'min' => 0],
            [['remark'], 'string', 'max' => 255],

            [['created_at', 'updated_at', 'deleted_at'], 'datetime', 'format' => 'yyyy-MM-dd HH:mm:ss'],

            [['user_id', 'operate', 'is_trash'], 'default', 'value' => 0],
            [['remark'], 'default', 'value' => ''],
            [['status'], 'default', 'value' => 1],

            [['user_id'], 'exist', 'skipOnError' => true, 'targetClass' => User::className(), 'targetAttribute' => ['user_id' => 'id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => Yii::t('app', 'ID'),
            'user_id' => Yii::t('app', '用户ID'),
            'operate' => Yii::t('app', '操作，1=>注册，2=>登录，3=>更新个人信息，4=>修改密码，5=>修改手机号码，6=>管理员创建'),
            'remark' => Yii::t('app', '备注'),
            'is_trash' => Yii::t('app', '是否删除，0=>否，1=>是'),
            'status' => Yii::t('app', '状态，0=>禁用，1=>启用'),
            'created_at' => Yii::t('app', '创建时间'),
            'updated_at' => Yii::t('app', '更新时间'),
            'deleted_at' => Yii::t('app', '删除时间'),
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getUser()
    {
        return $this->hasOne(User::className(), ['id' => 'user_id']);
    }
}
