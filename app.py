
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, EqualTo
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from wtforms.validators import Optional

#from wtforms.validators import Email

login_manager = LoginManager()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost:5433/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '123456'  # Change this to a secret key
login_manager.init_app(app)
db = SQLAlchemy(app)



class User(db.Model):

    def get_id(self):
        return str(self.id)
    @property
    def is_active(self):
        return True
    @property
    def is_authenticated(self):
        return True
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='Viewer')

    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)

class SteelMember(db.Model):
    cutting_list_number = db.Column(db.String, nullable=False)
    quantities = db.Column(db.Integer, nullable=False)
    weight_per_piece = db.Column(db.Float, nullable=False)
    surface_area_per_piece = db.Column(db.Float, nullable=False)
    total_weight = db.Column(db.Float, nullable=True)
    total_surface_area = db.Column(db.Float, nullable=True)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    dispatch_date = db.Column(db.DateTime, nullable=True)
    delivery_date = db.Column(db.DateTime, nullable=True)
    installation_date = db.Column(db.DateTime, nullable=True)
    
    cutting_list_number = db.Column(db.String, nullable=False)
    quantities = db.Column(db.Integer, nullable=False)
    weight_per_piece = db.Column(db.Float, nullable=False)
    surface_area_per_piece = db.Column(db.Float, nullable=False)
    total_weight = db.Column(db.Float, nullable=True)
    total_surface_area = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class FabricationStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fabrication_date = db.Column(db.Date, nullable=False)
    fabrication_release_number = db.Column(db.String, nullable=False)
    steel_member_id = db.Column(db.Integer, db.ForeignKey('steel_member.id'), nullable=False)


class DispatchStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dispatch_date = db.Column(db.Date, nullable=False)
    delivery_number = db.Column(db.String, nullable=False)
    steel_member_id = db.Column(db.Integer, db.ForeignKey('steel_member.id'), nullable=False)


class ReceiveStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receive_date = db.Column(db.Date, nullable=False)
    site_receive_number = db.Column(db.String, nullable=False)
    steel_member_id = db.Column(db.Integer, db.ForeignKey('steel_member.id'), nullable=False)



class FabricationForm(FlaskForm):
        pass


class DispatchForm(FlaskForm):
    dispatch_date = DateField('Dispatch Date', validators=[DataRequired()])
    delivery_number = StringField('Delivery Number', validators=[DataRequired()])
    submit = SubmitField('Update Dispatch Status')


class ReceiveForm(FlaskForm):
    receive_date = DateField('Receive Date', validators=[DataRequired()])
    site_receive_number = StringField('Site Receive Number', validators=[DataRequired()])
    installation_steps = TextAreaField('Installation Steps', validators=[DataRequired()])
    submit = SubmitField('Update Receive and Installation Status')

class QCForm(FlaskForm):
    qc_date = DateField('QC Date', validators=[DataRequired()])
    qc_report_number = StringField('QC Report Number', validators=[DataRequired()])
    qc_comments = TextAreaField('QC Comments', validators=[DataRequired()])
    submit = SubmitField('Update QC Status')


class InstallationForm(FlaskForm):
    receive_date = DateField('Receive Date', validators=[DataRequired()])
    site_receive_number = StringField('Site Receive Number', validators=[DataRequired()])
    submit = SubmitField('Update Status')
    dispatch_date = DateField('Dispatch Date', validators=[DataRequired()])
    delivery_number = StringField('Delivery Number', validators=[DataRequired()])
    submit = SubmitField('Update Status')
    fabrication_date = DateField('Fabrication Date', validators=[DataRequired()])
    fabrication_release_number = StringField('Fabrication Release Number', validators=[DataRequired()])
    submit = SubmitField('Update Status')

class FinalApprovalForm(FlaskForm):
    approval_date = DateField('Approval Date', validators=[DataRequired()])
    approval_comments = TextAreaField('Approval Comments', validators=[DataRequired()])
    submit = SubmitField('Update Approval Status')

class DocumentationForm(FlaskForm):
    document_date = DateField('Document Date', validators=[DataRequired()])
    document_number = StringField('Document Number', validators=[DataRequired()])
    document_comments = TextAreaField('Document Comments', validators=[DataRequired()])
    submit = SubmitField('Update Documentation Status')

class ClientFeedbackForm(FlaskForm):
    feedback_date = DateField('Feedback Date', validators=[DataRequired()])
    feedback_comments = TextAreaField('Feedback Comments', validators=[DataRequired()])
    client_satisfaction_level = SelectField('Satisfaction Level', choices=[('Very Satisfied', 'Very Satisfied'), ('Satisfied', 'Satisfied'), ('Neutral', 'Neutral'), ('Dissatisfied', 'Dissatisfied'), ('Very Dissatisfied', 'Very Dissatisfied')], validators=[DataRequired()])
    submit = SubmitField('Submit Feedback')

class MaintenanceForm(FlaskForm):
    service_date = DateField('Service Date', validators=[DataRequired()])
    service_comments = TextAreaField('Service Comments', validators=[DataRequired()])
    service_type = SelectField('Service Type', choices=[('Routine Maintenance', 'Routine Maintenance'), ('Repair', 'Repair'), ('Replacement', 'Replacement'), ('Inspection', 'Inspection')], validators=[DataRequired()])
    submit = SubmitField('Update Service Status')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  #  email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        user = User(username=form.username.data,role='Viewer') #"""email=form.email.data,""" 
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.context_processor
def inject_user():
    return {'current_user': current_user}

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role != 'Admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')
        
        user = User.query.get(user_id)
        if user and new_role != user.role:
            user.role = new_role
            db.session.add(user)
            db.session.commit()
            flash('User roles have been updated successfully.', 'success')

    return render_template('admin.html', users=users)

class SteelMemberForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    dispatch_date = DateField('Dispatch Date', format='%Y-%m-%d')
    delivery_date = DateField('Delivery Date', format='%Y-%m-%d')
    installation_date = DateField('Installation Date', format='%Y-%m-%d')
    submit = SubmitField('Add Member')
    delivery_date = DateField('Delivery Date', validators=[Optional()])
    installation_date = DateField('Installation Date', validators=[Optional()])

@app.route('/add_member', methods=['GET', 'POST'])
@login_required

def add_member():
    
    form = SteelMemberForm()
    if current_user.role not in ['Admin', 'Editor']:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        member = SteelMember(name=form.name.data, 
                             dispatch_date=form.dispatch_date.data,
                             delivery_date=form.delivery_date.data,
                             installation_date=form.installation_date.data,
                             user_id=current_user.id)
        db.session.add(member)
        db.session.commit()
        flash('Steel member added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_member.html', form=form)
   


@app.route('/edit_member/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_member(id):
    member = SteelMember.query.get_or_404(id)
    form = SteelMemberForm(obj=member)
    if current_user.role not in ['Admin', 'Editor']:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        if form.name.data:
            member.name = form.name.data
        if form.dispatch_date.data:
            member.dispatch_date = form.dispatch_date.data
        if form.delivery_date.data:
            member.delivery_date = form.delivery_date.data
        if form.installation_date.data:
            member.installation_date = form.installation_date.data
    
        try:
            db.session.commit()
            flash('Steel member updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error updating steel member: {e}', 'danger')
            return redirect(url_for('dashboard'))

    for field, errors in form.errors.items():
        for error in errors:
            flash(f"Error in {field}: {error}", 'danger')

    return render_template('edit_member.html', form=form, member=member)

@app.route('/bulk_edit', methods=['POST'])
def bulk_edit():
    member_ids = request.form.getlist('member_ids')
    dispatch_date = request.form.get('dispatch_date')
    delivery_date = request.form.get('delivery_date')
    installation_date = request.form.get('installation_date')
    for member_id in member_ids:
        member = SteelMember.query.get(member_id)
        if member:
            member.dispatch_date = dispatch_date
            member.delivery_date = delivery_date
            member.installation_date = installation_date
            db.session.commit()
    return redirect(url_for('dashboard'))




@app.route('/update_fabrication/<int:member_id>', methods=['GET', 'POST'])


@app.route('/update_dispatch/<int:member_id>', methods=['GET', 'POST'])
def update_dispatch(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = DispatchForm()
    if form.validate_on_submit():
        member.dispatch_status.dispatch_date = form.dispatch_date.data
        member.dispatch_status.delivery_number = form.delivery_number.data
        db.session.commit()
        flash('Dispatch status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.dispatch_date.data = member.dispatch_status.dispatch_date
        form.delivery_number.data = member.dispatch_status.delivery_number
    return render_template('update_dispatch.html', title='Update Dispatch Status', form=form, member=member)


@app.route('/update_receive/<int:member_id>', methods=['GET', 'POST'])
def update_receive(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = ReceiveForm()
    if form.validate_on_submit():
        member.receive_status.receive_date = form.receive_date.data
        member.receive_status.site_receive_number = form.site_receive_number.data
        member.receive_status.installation_steps = form.installation_steps.data
        db.session.commit()
        flash('Receive and installation status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.receive_date.data = member.receive_status.receive_date
        form.site_receive_number.data = member.receive_status.site_receive_number
        form.installation_steps.data = member.receive_status.installation_steps
    return render_template('update_receive.html', title='Update Receive and Installation Status', form=form, member=member)

@app.route('/update_qc/<int:member_id>', methods=['GET', 'POST'])
def update_qc(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = QCForm()
    if form.validate_on_submit():
        member.qc_status.qc_date = form.qc_date.data
        member.qc_status.qc_report_number = form.qc_report_number.data
        member.qc_status.qc_comments = form.qc_comments.data
        db.session.commit()
        flash('QC status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.qc_date.data = member.qc_status.qc_date
        form.qc_report_number.data = member.qc_status.qc_report_number
        form.qc_comments.data = member.qc_status.qc_comments
    return render_template('update_qc.html', title='Update QC Status', form=form, member=member)

@app.route('/update_installation/<int:member_id>', methods=['GET', 'POST'])
def update_installation(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = InstallationForm()
    if form.validate_on_submit():
        member.installation_steps = form.installation_steps.data
        member.installation_dates = form.installation_dates.data
        db.session.commit()
        flash('Installation steps updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_installation.html', form=form, member=member)
def update_receive(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = ReceiveForm()
    if form.validate_on_submit():
        member.receive_date = form.receive_date.data
        member.site_receive_number = form.site_receive_number.data
        db.session.commit()
        flash('Receive status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_receive.html', form=form, member=member)
def update_dispatch(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = DispatchForm()
    if form.validate_on_submit():
        member.dispatch_date = form.dispatch_date.data
        member.delivery_number = form.delivery_number.data
        db.session.commit()
        flash('Dispatch status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_dispatch.html', form=form, member=member)
def update_fabrication(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = FabricationForm()
    if form.validate_on_submit():
        member.fabrication_date = form.fabrication_date.data
        member.fabrication_release_number = form.fabrication_release_number.data
        db.session.commit()
        flash('Fabrication status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_fabrication.html', form=form, member=member)

@app.route('/update_approval/<int:member_id>', methods=['GET', 'POST'])
def update_approval(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = FinalApprovalForm()
    if form.validate_on_submit():
        member.approval_status.approval_date = form.approval_date.data
        member.approval_status.approval_comments = form.approval_comments.data
        db.session.commit()
        flash('Approval status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.approval_date.data = member.approval_status.approval_date
        form.approval_comments.data = member.approval_status.approval_comments
    return render_template('update_approval.html', title='Update Approval Status', form=form, member=member)

@app.route('/update_documentation/<int:member_id>', methods=['GET', 'POST'])
def update_documentation(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = DocumentationForm()
    if form.validate_on_submit():
        member.documentation_status.document_date = form.document_date.data
        member.documentation_status.document_number = form.document_number.data
        member.documentation_status.document_comments = form.document_comments.data
        db.session.commit()
        flash('Documentation status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.document_date.data = member.documentation_status.document_date
        form.document_number.data = member.documentation_status.document_number
        form.document_comments.data = member.documentation_status.document_comments
    return render_template('update_documentation.html', title='Update Documentation Status', form=form, member=member)

@app.route('/update_feedback/<int:member_id>', methods=['GET', 'POST'])
def update_feedback(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = ClientFeedbackForm()
    if form.validate_on_submit():
        member.feedback_status.feedback_date = form.feedback_date.data
        member.feedback_status.feedback_comments = form.feedback_comments.data
        member.feedback_status.client_satisfaction_level = form.client_satisfaction_level.data
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.feedback_date.data = member.feedback_status.feedback_date
        form.feedback_comments.data = member.feedback_status.feedback_comments
        form.client_satisfaction_level.data = member.feedback_status.client_satisfaction_level
    return render_template('update_feedback.html', title='Provide Feedback', form=form, member=member)

@app.route('/update_service/<int:member_id>', methods=['GET', 'POST'])
def update_service(member_id):
    member = SteelMember.query.get_or_404(member_id)
    form = MaintenanceForm()
    if form.validate_on_submit():
        member.service_status.service_date = form.service_date.data
        member.service_status.service_comments = form.service_comments.data
        member.service_status.service_type = form.service_type.data
        db.session.commit()
        flash('Service status updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.service_date.data = member.service_status.service_date
        form.service_comments.data = member.service_status.service_comments
        form.service_type.data = member.service_status.service_type
    return render_template('update_service.html', title='Update Service Status', form=form, member=member)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    search_name = request.args.get('search_name')
    from_dispatch_date = request.args.get('from_dispatch_date')
    to_dispatch_date = request.args.get('to_dispatch_date')
    # Add logic for other search criteria

    query = SteelMember.query

    if search_name:
        query = query.filter(SteelMember.name.contains(search_name))
    if from_dispatch_date and to_dispatch_date:
        query = query.filter(SteelMember.dispatch_date.between(from_dispatch_date, to_dispatch_date))
    # Add logic for other search criteria

    members = query.all()
    return render_template('dashboard.html', members=members)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # In case of database errors, rollback any changes
    return render_template('500.html'), 500

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/')
def home():
    return render_template('base.html')

if __name__ == '__main__':
    app.run(debug=True)
