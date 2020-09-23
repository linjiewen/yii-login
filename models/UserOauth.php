<?php

namespace yiiComponent\yiiLogin\models;

use Yii;

/**
 * This is the model class for table "{{%user_oauth}}".
 *
 * @property string $id
 * @property string $user_id 用户ID
 * @property int $type 类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台，6=>有赞
 * @property string $identity 身份信息
 * @property string $data 数据（json）
 * @property int $is_trash 是否删除，0=>否，1=>是
 * @property int $status 状态，0=>禁用，1=>启用
 * @property string $created_at 创建时间
 * @property string $updated_at 更新时间
 * @property string $deleted_at 删除时间
 *
 * @property User $user
 */
class UserOauth extends \yiiComponent\yiiLogin\models\BaseActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return '{{%user_oauth}}';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['id', 'user_id', 'type', 'is_trash', 'status'], 'integer', 'min' => 0],
            [['data'], 'required'],
            [['data'], 'string'],
            [['identity'], 'string', 'max' => 64],

            [['created_at', 'updated_at', 'deleted_at'], 'datetime', 'format' => 'yyyy-MM-dd HH:mm:ss'],

            [['user_id', 'type', 'is_trash'], 'default', 'value' => 0],
            [['identity', 'data'], 'default', 'value' => ''],
            [['status'], 'default', 'value' => 1],
            [['deleted_at'], 'default', 'value' => null],

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
            'type' => Yii::t('app', '类型，1=>微信公众号，2=>微信开放平台，3=>微信小程序，4=>新浪微博开放平台，5=>QQ开放平台，6=>有赞'),
            'identity' => Yii::t('app', '身份信息'),
            'data' => Yii::t('app', '数据（json）'),
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
