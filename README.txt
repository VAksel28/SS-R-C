Для создания изображения с шифром используйте функцию
stego_image(shamirs_k, shamirs_n)
Для расшифровки изображения используйте функцию
decrypt_stego_image(stego_image)


В свете того, что тема маркировки генераций ИИ все набирает обороты, я вспомнил про такую штуку, как стеганография. Опыта с ней я не имел, только краем уха слышал на парах, когда еще был студентом, что это способ положить в фото, аудио или видео какую то информацию.Немного поискав информацию я понял, что стенографические методы достаточно неустойчивы, и от сильных изменений не защитят.
и тут я наткнулся на статью о методе, устойчивом к повреждениям данных. https://cyberleninka.ru/article/n/steganograficheskiy-metod-ustoychivyy-k-povrezhdeniyu-dannyh/viewer
Даный метод основан на схеме Шамира, и записывает в изображение не одно зашифрованное сообщение, а несколько, что позволяет восстановить данные даже при повреждениях изображения.
Ну я и решил попробовать реализовать этот метод.

Первый этап подразумевает различение секрета на n частей. Тут можно было схалтурить и взять готовое решение из библиотеки Crypto, что я и сделал.
