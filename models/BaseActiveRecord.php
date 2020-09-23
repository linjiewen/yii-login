<?php

namespace yiiComponent\yiiLogin\models;

use yii\behaviors\AttributeTypecastBehavior;
use app\components\behaviors\TimeBehavior;

/**
 * 基础活跃记录类
 */
class BaseActiveRecord extends \yii\db\ActiveRecord
{
    /**
     * 行为
     *
     * @return array
     */
    public function behaviors()
    {
        return array_merge(parent::behaviors(), [
            'typecast' => [
                'class' => AttributeTypecastBehavior::className(),
                'typecastAfterValidate' => true,
                'typecastBeforeSave' => true,
                'typecastAfterFind' => true,
            ],
            'time' => [
                'class' => TimeBehavior::className(),
            ],
        ]);
    }
}
