from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField, DateTimeField, IntegerField
from wtforms.validators import DataRequired
import os
import matplotlib.pyplot as plt
from flask_wtf.csrf import CSRFProtect
import io
import base64
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from collections import defaultdict
from datetime import datetime, timezone, timedelta  
import pytz  
from sqlalchemy.orm import joinedload


csrf = CSRFProtect()

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    full_name = StringField('Full Name', validators=[DataRequired()])
    qualification = StringField('Qualification')
    dob = DateField('Date of Birth', format='%Y-%m-%d')
    
class AddSubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])    

class EditSubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    
class AddChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])  
    
class ChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])  

class QuizForm(FlaskForm):
    name = StringField('Quiz Name', validators=[DataRequired()])
    subject_id = SelectField('Subject', coerce=int, validators=[DataRequired()])
    chapter_id = SelectField('Chapter', coerce=int, validators=[DataRequired()])
    date_of_quiz = DateTimeField('Date of Quiz', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    time_duration = IntegerField('Time Duration (in minutes)', validators=[DataRequired()])

class QuestionForm(FlaskForm):
    question_statement = StringField("Question", validators=[DataRequired()])
    option1 = StringField("Option 1", validators=[DataRequired()])
    option2 = StringField("Option 2", validators=[DataRequired()])
    option3 = StringField("Option 3")
    option4 = StringField("Option 4")
    correct_option = SelectField("Correct Option", choices=[('1', 'Option 1'), ('2', 'Option 2'), ('3', 'Option 3'), ('4', 'Option 4')])
    submit = SubmitField("Add Question")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_masterV1d.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "quizmastersecret"
db = SQLAlchemy(app)
csrf.init_app(app)


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = generate_password_hash("admin123")
submit = SubmitField('Login')

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hashed_password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    qualification = db.Column(db.String(120), nullable=True)
    dob = db.Column(db.Date, nullable=True)
    
    
    scores = db.relationship('Score', back_populates='user')

class Subject(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    

    chapters = db.relationship('Chapter', back_populates='subject', cascade="all, delete-orphan")
    quizzes = db.relationship('Quiz', back_populates='subject', cascade="all, delete-orphan")

class Chapter(db.Model):
    __tablename__ = 'chapters'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    

    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)
    
    subject = db.relationship('Subject', back_populates='chapters')
    quizzes = db.relationship('Quiz', back_populates='chapter', cascade="all, delete")
    
    
class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapters.id'), nullable=False)  
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)  
    date_of_quiz = db.Column(db.DateTime, nullable=False)
    time_duration = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String)

    
    chapter = db.relationship('Chapter', back_populates='quizzes')
    subject = db.relationship('Subject', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz')
    scores = db.relationship('Score', back_populates='quiz')


    
class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_statement = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=True)
    option4 = db.Column(db.String(200), nullable=True)
    correct_option = db.Column(db.Integer, nullable=False)
    
    
    quiz = db.relationship('Quiz', back_populates='questions')



class Score(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    
    
    user = db.relationship('User', back_populates='scores')
    quiz = db.relationship('Quiz', back_populates='scores')


    
class UserAnswer(db.Model):
    __tablename__ = 'user_answers'
    id = db.Column(db.Integer, primary_key=True)
    
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    selected_option = db.Column(db.String, nullable=False)

    
    user = db.relationship('User', backref='answers')
    quiz = db.relationship('Quiz', backref='user_answers')
    question = db.relationship('Question', backref='user_answers')

    


# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD, password):
            session['admin'] = True  
            flash('Admin login successful', 'success')
            return redirect(url_for('admin_dashboard'))  
        
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.hashed_password, password):
            session['user_id'] = user.id
            flash('Login successful', 'success')
            return redirect(url_for('user_dashboard'))  

        flash('Invalid credentials', 'danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        full_name = form.full_name.data
        qualification = form.qualification.data
        dob = form.dob.data

        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            hashed_password=hashed_password,
            full_name=full_name,
            qualification=qualification,
            dob=dob
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/admin_dashboard')
def admin_dashboard():
    total_subjects = Subject.query.count()  
    total_users = User.query.count()  
    total_quizzes = Quiz.query.count() 
     # Count of all quizzes
    subjects = Subject.query.all()  
    users = User.query.all()  
    quiz = Quiz.query.all() 

    return render_template('admin_dashboard.html', 
                           total_subjects=total_subjects, 
                           total_users=total_users,
                           total_quizzes=total_quizzes,
                           subjects=subjects, 
                           users=users,
                           quiz=quiz)
    
    
@app.route('/add_subject', methods=['GET', 'POST'])
def add_subject():
    form = AddSubjectForm()
    if form.validate_on_submit():  
        name = form.name.data
        description = form.description.data
        new_subject = Subject(name=name, description=description)
        db.session.add(new_subject)
        db.session.commit()
        flash('Subject added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_subject.html', form=form)

@app.route('/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    subject = Subject.query.get_or_404(subject_id)
    form = EditSubjectForm(obj=subject)  

    if form.validate_on_submit():
        subject.name = form.name.data
        subject.description = form.description.data
        db.session.commit()
        flash('Subject updated successfully')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_subject.html', form=form, subject=subject)


@app.route('/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    subject = Subject.query.get_or_404(subject_id)
    
    try:
    
        chapters = Chapter.query.filter_by(subject_id=subject.id).all()

        for chapter in chapters:
            quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
            
            for quiz in quizzes:
                UserAnswer.query.filter_by(quiz_id=quiz.id).delete()
                
            
                Score.query.filter_by(quiz_id=quiz.id).delete()
                
            
                Question.query.filter_by(quiz_id=quiz.id).delete()

                
                db.session.delete(quiz)
            
            
            db.session.delete(chapter)
        
    
        db.session.delete(subject)
        db.session.commit()
        
        flash('Subject and all its related data (chapters, quizzes, questions, user answers) deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting subject: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/quiz_management')
def quiz_management():  
    return render_template('quiz_management.html', quizzes=Quiz.query.all())

@app.route('/add_quiz', methods=['GET', 'POST'])
def add_quiz():
    form = QuizForm()


    form.chapter_id.choices = [(chapter.id, chapter.name) for chapter in Chapter.query.all()]
    
    form.subject_id.choices = [(subject.id, subject.name) for subject in Subject.query.all()]

    if form.validate_on_submit():
    
        name = form.name.data
        chapter_id = form.chapter_id.data
        subject_id = form.subject_id.data
        date_of_quiz = form.date_of_quiz.data
        time_duration = form.time_duration.data

        
        new_quiz = Quiz(
            remarks=name,
            chapter_id=chapter_id,
            subject_id = subject_id,
            date_of_quiz=date_of_quiz,
            time_duration=time_duration
        )

        try:
            db.session.add(new_quiz)
            db.session.commit()
            flash('Quiz added successfully!', 'success')
            return redirect(url_for('quiz_management'))  
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding quiz: {e}", 'danger')

    
    today_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M')
    return render_template('add_quiz.html', form=form, today_date=today_date)


@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
def delete_quiz(quiz_id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)

    try:
        
        UserAnswer.query.filter_by(quiz_id=quiz.id).delete()

        
        Score.query.filter_by(quiz_id=quiz.id).delete()

        
        Question.query.filter_by(quiz_id=quiz.id).delete()

        
        db.session.delete(quiz)

        
        db.session.commit()

        flash('Quiz and all its related data (questions, scores, user answers) deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting quiz: {str(e)}', 'danger')

    return redirect(url_for('quiz_management'))

@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == 'POST':
        try:
            quiz.date_of_quiz = datetime.fromisoformat(request.form['date_of_quiz'])
            quiz.time_duration = int(request.form['time_duration'])
            quiz.remarks = request.form['remarks']
            db.session.commit()
            flash('Quiz updated successfully', 'success')
            return redirect(url_for('quiz_management'))
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'danger')
    
    
    formatted_date = quiz.date_of_quiz.strftime('%Y-%m-%dT%H:%M')
    return render_template('edit_quiz.html', 
                         quiz=quiz,
                         formatted_date=formatted_date)


@app.route('/add_chapter/<int:subject_id>', methods=['GET', 'POST'])
def add_chapter(subject_id):
    subject = Subject.query.get_or_404(subject_id)  
    form = AddChapterForm()

    if form.validate_on_submit():  
        chapter_name = form.name.data
        chapter_description = form.description.data

        
        new_chapter = Chapter(name=chapter_name, description=chapter_description, subject_id=subject.id)
        db.session.add(new_chapter)
        db.session.commit()

        flash('Chapter added successfully!', 'success')
        return redirect(url_for('view_subject', subject_id=subject.id))  

    return render_template('add_chapter.html', form=form, subject_id=subject_id)

@app.route('/edit_chapter/<int:chapter_id>', methods=['GET', 'POST'])
def edit_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    form = ChapterForm(obj=chapter)  

    if form.validate_on_submit():  
        chapter.name = form.name.data
        chapter.description = form.description.data
        db.session.commit()
        flash('Chapter updated successfully!', 'success')
        return redirect(url_for('view_subject', subject_id=chapter.subject_id))
    
    return render_template('edit_chapter.html', form=form, chapter=chapter)

@app.route('/delete_chapter/<int:chapter_id>', methods=['GET', 'POST'])
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id  

    try:
        
        quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
        
        for quiz in quizzes:
            
            UserAnswer.query.filter_by(quiz_id=quiz.id).delete()

            
            Score.query.filter_by(quiz_id=quiz.id).delete()

            
            Question.query.filter_by(quiz_id=quiz.id).delete()
            
            
            db.session.delete(quiz)
        
        
        db.session.delete(chapter)
        db.session.commit()
        
        flash('Chapter and all its related data (quizzes, questions, scores, user answers) deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting chapter: {str(e)}', 'danger')

    return redirect(url_for('view_subject', subject_id=subject_id))



@app.route('/view_subject/<int:subject_id>')
def view_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    return render_template('view_subject.html', subject=subject)


@app.route('/add_question/<int:quiz_id>', methods=['GET', 'POST'])
def add_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)  
    form = QuestionForm()

    if form.validate_on_submit():  
        new_question = Question(
            quiz_id=quiz_id,
            question_statement=form.question_statement.data,
            option1=form.option1.data,
            option2=form.option2.data,
            option3=form.option3.data or None, 
            option4=form.option4.data or None,
            correct_option=int(form.correct_option.data)  
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully', 'success')
        return redirect(url_for('quiz_management'))  

    return render_template('add_question.html', quiz=quiz, form=form)  
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    
    if not query:
        flash('Please enter a search term', 'warning')
        return redirect(url_for('admin_dashboard'))

    search_pattern = f'%{query}%'
    
    users = User.query.filter(User.username.ilike(search_pattern)).all()
    subjects = Subject.query.filter(Subject.name.ilike(search_pattern)).all()
    quizzes = Quiz.query.filter(Quiz.remarks.ilike(search_pattern)).all()

    return render_template('search_result.html',
                         query=query,
                         users=users,
                         subjects=subjects,
                         quizzes=quizzes)



@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])
    
    
    current_time = datetime.utcnow()  


    
    quizzes = Quiz.query.filter(
        Quiz.date_of_quiz >= current_time  
    ).options(
        db.joinedload(Quiz.questions),  
        db.joinedload(Quiz.chapter).joinedload(Chapter.subject)  
    ).all()

    quiz_data = []
    for quiz in quizzes:
        quiz_end = quiz.date_of_quiz + timedelta(minutes=quiz.time_duration)
        status = 'active' if current_time <= quiz_end else 'expired'

        quiz_data.append({
            'quiz': quiz,
            'status': status,
            'question_count': len(quiz.questions),
            'subject': quiz.chapter.subject if quiz.chapter else None,
            'chapter': quiz.chapter if quiz.chapter else None,
            'attempted': Score.query.filter_by(
                user_id=user.id, 
                quiz_id=quiz.id
            ).first() is not None
        })

    return render_template(
        'user_dashboard.html',
        user=user,
        quizzes=quiz_data,
        datetime=datetime,  
        timedelta=timedelta,  
        pytz=pytz  
    )



@app.route('/view_quiz/<int:quiz_id>')
def view_quiz(quiz_id):
    
    quiz = Quiz.query.options(joinedload(Quiz.questions))\
                     .get_or_404(quiz_id)
    

    question_count = len(quiz.questions)
    
    return render_template('view_quiz.html',
                         quiz=quiz,
                         question_count=question_count)


@app.route('/start_quiz/<int:quiz_id>', methods=['POST'])
def start_quiz(quiz_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    quiz = Quiz.query.options(db.joinedload(Quiz.questions)).get_or_404(quiz_id)

    if not quiz.questions:
        flash('This quiz has no questions', 'warning')
        return redirect(url_for('user_dashboard'))

    
    IST = pytz.timezone('Asia/Kolkata')

    current_time_ist = datetime.now(timezone.utc).astimezone(IST)


    quiz_start_time_ist = quiz.date_of_quiz.astimezone(IST)

    if current_time_ist < quiz_start_time_ist:
        flash(f'The quiz will start at {quiz_start_time_ist.strftime("%Y-%m-%d %H:%M:%S")} IST. Please wait.', 'warning')
        return redirect(url_for('user_dashboard'))

    end_time_ist = current_time_ist + timedelta(minutes=quiz.time_duration)

    session.update({
        'quiz_id': quiz_id,
        'question_idx': 0,
        'answers': {},
        'start_time': current_time_ist.timestamp(),
        'end_time': end_time_ist.timestamp()
    })

    return redirect(url_for('quiz_question', quiz_id=quiz_id))

@app.route('/quiz_question/<int:quiz_id>', methods=['GET', 'POST'])
def quiz_question(quiz_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        quiz = Quiz.query.options(db.joinedload(Quiz.questions)).get_or_404(quiz_id)
        questions = quiz.questions
        current_idx = session.get('question_idx', 0)
        
        
        end_time = datetime.fromtimestamp(session['end_time'], tz=timezone.utc)
        current_time = datetime.now(timezone.utc)
        remaining_seconds = int((end_time - current_time).total_seconds())

        if remaining_seconds <= 0:
            return redirect(url_for('submit_quiz', quiz_id=quiz_id))

        if request.method == 'POST':
            if 'answer' not in request.form:
                flash('Please select an answer', 'warning')
                return redirect(url_for('quiz_question', quiz_id=quiz_id))
                
            session['answers'][str(current_idx)] = request.form['answer']
            session['question_idx'] = current_idx + 1

            if current_idx + 1 >= len(questions):
                return redirect(url_for('submit_quiz', quiz_id=quiz_id))

        question = questions[session['question_idx']]
        
        return render_template(
            'quiz_question.html',
            question=question,
            current_question_idx=session['question_idx'],
            total_questions=len(questions),
            remaining_seconds=remaining_seconds
        )

    except IndexError:
        return redirect(url_for('submit_quiz', quiz_id=quiz_id))
    except Exception as e:
        app.logger.error(f"Quiz error: {str(e)}")
        abort(500)


@app.route('/submit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def submit_quiz(quiz_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions
    user_answers = session.get('answers', {})  

    print(f"Stored User Answers: {user_answers}")   

    
    score = 0
    user_answers_entries = []  

    
    user_answers_list = list(user_answers.values()) 

    for index, question in enumerate(questions):
        question_id = str(question.id)  
        correct_option = str(question.correct_option)

    
        user_answer = user_answers_list[index] if index < len(user_answers_list) else None

        print(f"Processing Question ID: {question_id}, User Answer: {user_answer}, Correct Option: {correct_option}") 

    
        if user_answer is not None and user_answer == correct_option:
            score += 1  

        
        user_answers_entries.append(
            UserAnswer(
                user_id=user_id,
                quiz_id=quiz_id,
                question_id=question.id,
                selected_option=user_answer if user_answer else "Not Answered"
            )
        )

    
    db.session.bulk_save_objects(user_answers_entries)

    
    new_score = Score(user_id=user_id, quiz_id=quiz_id, score=score)
    db.session.add(new_score)
    db.session.commit()


    session.pop('quiz_id', None)
    session.pop('question_idx', None)
    session.pop('start_time', None)
    session.pop('end_time', None)
    session.pop('answers', None)

    return redirect(url_for('user_dashboard'))


@app.route('/score', methods=['GET', 'POST'])
def score():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    search_query = request.args.get('query', '')
    
    
    scores = Score.query.filter_by(user_id=user_id)\
                       .join(Quiz)\
                       .options(db.joinedload(Score.quiz))\
                       .order_by(Score.id.desc())

    if search_query:
        scores = scores.filter(
            Subject.name.ilike(f"%{search_query}%") |
            Quiz.date_of_quiz.ilike(f"%{search_query}%") |
            Score.score.ilike(f"%{search_query}%")  
        )

    scores = scores.all()

    return render_template('score.html', 
                         scores=scores,
                         search_query=search_query)



@app.route('/summary')
def summary():
    quizzes = Quiz.query.all()
    
    #Subject-wise quiz count for Bar Chart
    subject_quiz_count = {}
    for quiz in quizzes:
        chapter_name = quiz.chapter.name
        if chapter_name not in subject_quiz_count:
            subject_quiz_count[chapter_name] = 0
        subject_quiz_count[chapter_name] += 1

    
    subjects = list(subject_quiz_count.keys())
    quiz_counts = list(subject_quiz_count.values())
    
    #Month-wise quiz count for Pie Chart
    month_quiz_count = {}
    for quiz in quizzes:
        month = quiz.date_of_quiz.month
        month_name = datetime(2025, month, 1).strftime('%B')  
        if month_name not in month_quiz_count:
            month_quiz_count[month_name] = 0
        month_quiz_count[month_name] += 1

    
    months = list(month_quiz_count.keys())
    month_counts = list(month_quiz_count.values())

    
    fig, ax = plt.subplots()
    ax.bar(subjects, quiz_counts)
    ax.set_title('Subject-wise Quizzes')
    ax.set_xlabel('Subject')
    ax.set_ylabel('Number of Quizzes')

    
    bar_img = io.BytesIO()
    FigureCanvas(fig).print_png(bar_img)
    bar_img.seek(0)
    bar_img_base64 = base64.b64encode(bar_img.getvalue()).decode('utf8')

    
    fig2, ax2 = plt.subplots()
    ax2.pie(month_counts, labels=months, autopct='%1.1f%%', startangle=90)
    ax2.set_title('Monthly Quiz Distribution')

   
    pie_img = io.BytesIO()
    FigureCanvas(fig2).print_png(pie_img)
    pie_img.seek(0)
    pie_img_base64 = base64.b64encode(pie_img.getvalue()).decode('utf8')

    return render_template('summary.html', bar_img_base64=bar_img_base64, pie_img_base64=pie_img_base64)



@app.route('/admin_summary')
def admin_summary():
    quizzes = Quiz.query.all()
    scores = Score.query.all()
    users = User.query.all()

    #Subject-wise Top Scores for Bar Chart
    subject_scores = defaultdict(list)  
    for score in scores:
        quiz = score.quiz
        subject_name = quiz.chapter.name
        subject_scores[subject_name].append(score.score)

    
    top_scores = {subject: max(scores) if scores else 0 for subject, scores in subject_scores.items()}
    subjects = list(top_scores.keys())
    top_scores_values = list(top_scores.values())

    #Subject-wise User Attempts for Pie Chart
    subject_user_attempts = defaultdict(int)  
    for score in scores:
        quiz = score.quiz
        subject_name = quiz.chapter.name
        subject_user_attempts[subject_name] += 1

    subjects_pie = list(subject_user_attempts.keys())
    user_attempts = list(subject_user_attempts.values())

    
    fig, ax = plt.subplots()
    ax.bar(subjects, top_scores_values, color='blue')
    ax.set_title('Top Scores per Subject')
    ax.set_xlabel('Subjects')
    ax.set_ylabel('Top Scores')

    
    bar_img = io.BytesIO()
    FigureCanvas(fig).print_png(bar_img)
    bar_img.seek(0)
    bar_img_base64 = base64.b64encode(bar_img.getvalue()).decode('utf8')

    
    fig2, ax2 = plt.subplots()
    ax2.pie(user_attempts, labels=subjects_pie, autopct='%1.1f%%', startangle=90)
    ax2.set_title('Subject-wise User Attempts')

    
    pie_img = io.BytesIO()
    FigureCanvas(fig2).print_png(pie_img)
    pie_img.seek(0)
    pie_img_base64 = base64.b64encode(pie_img.getvalue()).decode('utf8')

    return render_template('admin_summary.html', bar_img_base64=bar_img_base64, pie_img_base64=pie_img_base64)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)