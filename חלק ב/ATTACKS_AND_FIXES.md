# חלק ב — שימוש בטכניקות SQLi + XSS

מסמך זה מדגים את ארבעת הסעיפים שנדרשו: שתי דוגמאות התקפה (Stored XSS, SQL Injection)
ושני פתרונות (קידוד תווים מיוחדים, שימוש ב-Parameters). כל ההדגמות בוצעו מול
השרת המקומי (`localhost`) של גרסת חלק ב' הפגיעה בכוונה, ולא מול שרת ייצור.

---

## 1. הדגמת התקפת Stored XSS

**מיקום הפגיעות:** `templates/system.html`, טבלת הלקוחות. השדה `name` (וגם `email`,
`phone`, `address`) מודפס עם פילטר `|safe`:

```jinja
<th scope="row">{{ c.name|safe }}</th>
```

הפילטר `|safe` מורה ל-Jinja2 **לא** לבצע escaping — כל HTML/JavaScript שהוזן
בשדה "שם לקוח" ייכנס כקוד HTML חי לדף, וירוץ אצל כל משתמש שצופה ברשימת הלקוחות.

**הפעלה:** נרשמנו למערכת, ובטופס "הוספת לקוח" הוזן בשדה השם:

```html
<img src=x onerror=document.title=`XSS-POC-EXECUTED`>
```

(ה-payload נבחר ללא גרשים בכוונה, כדי שלא לשבור את משפט ה-SQL — ראו סעיף 2 למטה.)

**תוצאה בפועל:**
- בלוג השרת נרשמה בקשת `GET /x` — כלומר הדפדפן ניסה לטעון את "x" כתמונה אמיתית,
  מה שמוכיח שהתג `<img>` נטען כ-HTML אמיתי ולא הוצג כטקסט.
- כשטעינת התמונה נכשלה, קוד ה-`onerror` רץ ושינה את כותרת הלשונית ל-
  `XSS-POC-EXECUTED`.
- בטבלת הלקוחות מוצג אייקון תמונה שבורה במקום השם (`screenshots/02_xss_executed.jpg`),
  הוכחה חזותית שה-HTML בוצע ולא הוצג כטקסט.

| לפני השליחה | אחרי הביצוע (XSS רץ) |
|---|---|
| `screenshots/01_xss_payload_before.jpg` | `screenshots/02_xss_executed.jpg` |

**השפעה אמיתית:** זהו Stored XSS — ה-payload נשמר במסד הנתונים ורץ אצל **כל** משתמש
שיצפה ברשימת הלקוחות (לא רק אצל התוקף), ויכול לשמש לגניבת עוגיות סשן, ביצוע פעולות
בשם המשתמש המחובר, הפניה לאתר זדוני ועוד.

---

## 2. הדגמת התקפת SQL Injection

**מיקום הפגיעות:** `db.py`, בכל פונקציה שמקבלת קלט משתמש, השאילתה נבנית
בהדבקת מחרוזות (string concatenation) במקום placeholders:

```python
# db.py - add_customer (הדגמה)
return _run(
    "INSERT INTO customers (name, email, phone, address, created_by, created_at) VALUES ('"
    + name + "', '" + email + "', '" + phone + "', '" + address + "', "
    + str(int(created_by)) + ", " + str(int(time.time())) + ")"
)
```

אותה שיטה פגיעה קיימת גם ב-`get_user_by_username` (התחברות), `create_user` (הרשמה),
`find_valid_reset_code` (איפוס סיסמה) ועוד.

**הפעלה:** באותו טופס "הוספת לקוח", כשהוזן בשדה השם payload עם גרש בודד:

```html
<img src=x onerror="document.title='XSS-POC-EXECUTED'">
```

השרת החזיר שגיאת 500, ובלוג מופיעה החריגה:

```
sqlite3.OperationalError: near "XSS": syntax error
```

כלומר הגרש (`'`) שבתוך הקלט **שבר את מבנה משפט ה-SQL** וגרם לו להתפרש כקוד SQL נוסף
ולא כטקסט — זו ההוכחה הקלאסית לקיום הזרקת SQL. ראו `screenshots/03_sqli_syntax_error.jpg`.

**השפעה אמיתית מעבר לשגיאה:** מכיוון שהקלט הופך לחלק ממשפט ה-SQL עצמו, תוקף שיודע
לנסח payload תקין (למשל `UNION SELECT` במקום תו שבור) יכול, עקרונית, לשלוף נתונים
מטבלאות אחרות, לעקוף לוגיקת שאילתה, או לשנות/למחוק רשומות — תלוי באיזו נקודת
הזרקה משתמשים ואיך המידע חוזר למסך.

---

## 3. פתרון מול ה-Stored XSS — קידוד תווים מיוחדים (Output Encoding)

הפתרון קיים בפועל בחלק א' (הגרסה המאובטחת), באותו קובץ תבנית בדיוק:

```jinja
<!-- חלק א: templates/system.html -->
<th scope="row">{{ c.name }}</th>
```

**ההבדל היחיד הוא הסרת `|safe`.** Jinja2 מבצע **autoescape** כברירת מחדל על כל
`{{ ... }}` בקובצי `.html` — כל תו מיוחד (`<`, `>`, `"`, `'`, `&`) מומר אוטומטית
ל-HTML entity המקביל (למשל `<` הופך ל-`&lt;`). כך ה-payload `<img src=x onerror=...>`
מוצג כטקסט גלוי בלבד (`&lt;img src=x onerror=...&gt;`) ולעולם לא רץ כקוד.

בדקנו זאת בפועל מול חלק א': אותו סוג payload (עם תג `<script>` וגרש) הוזן לשדה השם,
הבקשה הצליחה (302, ללא שגיאת שרת), וכותרת הלשונית **לא** השתנתה — כלומר ה-JavaScript
לא רץ, בניגוד למה שקרה בחלק ב'.

> כלל אצבע: `|safe` משמש **רק** לתוכן שהאתר עצמו יצר ובוטח בו באופן מלא (לדוגמה HTML
> קבוע בתוך תבנית). תוכן שמגיע מהמשתמש (שם, כתובת, הערה וכו') לעולם לא אמור לקבל `|safe`.

---

## 4. פתרון מול ה-SQL Injection — שימוש ב-Parameters

הפתרון קיים בפועל בחלק א', באותו קובץ `db.py` בדיוק, לכל פונקציה:

```python
# חלק א: db.py - add_customer
return _run(
    "INSERT INTO customers (name, email, phone, address, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    (name, email, phone, address, created_by, int(time.time())),
)
```

**ההבדל:** במקום להדביק את ערכי המשתמש לתוך מחרוזת ה-SQL, משתמשים ב-placeholders
(`?`) ומעבירים את הערכים בנפרד כ-tuple של פרמטרים ל-`cur.execute(sql, params)`.
מנוע ה-SQLite/MySQL מתייחס לפרמטרים האלה **אך ורק כנתון**, ולעולם לא כחלק מתחביר
השאילתה — גם אם הערך מכיל גרשים, מרכאות, או מילות מפתח של SQL.

בדקנו זאת בפועל: אותו payload בדיוק עם גרש בודד (`O'Brien<script>...`) הוזן בחלק א',
הבקשה הצליחה (302, ללא שגיאת 500), והרשומה נשמרה ומוצגת כטקסט רגיל — בלי לשבור
את השאילתה ובלי להריץ קוד.

**חלופה שקולה — Stored Procedures:** דרך נוספת, מקובלת בעיקר ב-MySQL/SQL Server,
היא להעביר את הלוגיקה לפרוצדורה מאוחסנת במסד הנתונים (`CALL add_customer(?, ?, ?, ?, ?)`)
שבה הפרמטרים מוקלדים (typed) מראש על ידי מנוע ה-DB. העיקרון זהה ל-Parameters:
הפרדה מוחלטת בין קוד ה-SQL לבין הנתונים שמגיעים מהמשתמש.

---

## סיכום טבלה

| # | מה נדרש | איפה מודגם |
|---|---|---|
| 1 | דוגמה ל-Stored XSS | `templates/system.html` (`\|safe`) + screenshots 01–02 |
| 2 | דוגמה ל-SQL Injection | `db.py` (concatenation) + screenshot 03 + לוג שגיאה |
| 3 | פתרון ל-XSS — קידוד תווים | חלק א' `templates/system.html` (autoescape, בלי `\|safe`) |
| 4 | פתרון ל-SQLi — Parameters | חלק א' `db.py` (placeholders `?` + tuple פרמטרים) |
