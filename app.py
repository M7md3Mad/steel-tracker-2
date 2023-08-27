from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, EqualTo
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from wtforms.validators import Optional
from datetime import datetime
from flask_principal import Principal, Permission, RoleNeed
from matplotlib import pyplot as plt
from datetime import date, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost:5433/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '123456'  # Change this to a secret key
# Initialize Flask-Login and Flask-Principal
login_manager = LoginManager()
login_manager.init_app(app)
principals = Principal(app)
db = SQLAlchemy(app)


class User(db.Model, UserMixin):

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
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)  # Foreign key to Role model
    role = db.relationship('Role', backref='users')  # Relationship to Role model
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    access_values = db.Column(db.String(200)) # Define specific values that can be accessed
    create_reports = db.Column(db.Boolean) # Define if the role can create reports
    # Additional fields for specific permissions can be added here
    # Define specific permissions
    can_access_fabrication = db.Column(db.Boolean, default=False)
    can_edit_fabrication = db.Column(db.Boolean, default=False)
    # Add more permissions as needed
    # ...
    def __repr__(self):
        return f"<Role {self.name}>"

# Define roles
admin_permission = Permission(RoleNeed('admin'))
fabrication_permission = Permission(RoleNeed('fabrication'))
dispatch_permission = Permission(RoleNeed('dispatch'))
project_permission = Permission(RoleNeed('project'))
project_manager_permission = Permission(RoleNeed('project'))

""" @app.before_request
def restrict_access_to_routes():
    # Restricting access to routes based on user roles
    if not current_user.is_authenticated:
        return
    user_role = current_user.role.name if current_user.role.name else ""
    if request.endpoint in ["add_member", "edit_member", "delete_member"] and user_role != "project_manager":
        return redirect(url_for('dashboard'))
    if request.endpoint in ["update_fabrication"] and user_role != "fabrication_engineer":
        return redirect(url_for('dashboard'))
    if request.endpoint in ["update_dispatch"] and user_role != "dispatch_engineer":
        return redirect(url_for('dashboard'))
    if request.endpoint in ["update_receive", "update_installation"] and user_role not in ["site_engineer", "supervisor"]:
        return redirect(url_for('dashboard'))
 """
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def create_admin_user():
    # Check if there are any users in the User table
    if not User.query.first():
        # Check if the admin role exists; if not, create it
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator')
            db.session.add(admin_role)
            db.session.commit()

        # Create the admin user
        admin = User(username='admin')
        admin.set_password('admin')
        admin.role = admin_role

        # Add admin user to the database
        db.session.add(admin)
        db.session.commit()

# Call the function to ensure admin user is created when the app runs
with app.app_context():
   create_admin_user()


class SteelMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=True)
    cutting_list_number = db.Column(db.String, nullable=True)
    quantities = db.Column(db.Integer, nullable=True)
    weight_per_piece = db.Column(db.Float, nullable=True)
    surface_area_per_piece = db.Column(db.Float, nullable=True)
    total_weight = db.Column(db.Float, nullable=True)
    total_surface_area = db.Column(db.Float, nullable=True)
    dispatch_date = db.Column(db.DateTime, nullable=True)
    delivery_date = db.Column(db.DateTime, nullable=True)
    installation_date = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)


    @property
    def total_weight(self):
        return self.quantities * self.weight_per_piece

    @property
    def total_surface_area(self):
        return self.quantities * self.surface_area_per_piece


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

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    status = db.Column(db.String(50))
    # Additional fields and relationships can be added here
    # Relationship with SteelMember
    members = db.relationship('SteelMember', backref='project', lazy=True)
    
    def __repr__(self):
        return f"<Project {self.name}>"

class ProjectForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired()])
    submit = SubmitField('Create Project')

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

class InstallationStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('steel_member.id'))
    step1_date = db.Column(db.Date)
    step2_date = db.Column(db.Date)
    # Add additional steps as needed


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

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100), nullable=False)  # e.g., 'Fabrication', 'Dispatch', 'Project'
    report_type = db.Column(db.String(100), nullable=False)  # e.g., 'Delivery Note', 'Fabrication Release'
    generated_on = db.Column(db.DateTime, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)  # The actual content or data of the report

    # Foreign key to link report to a specific steel member
    steel_member_id = db.Column(db.Integer, db.ForeignKey('steel_member.id'), nullable=False)
    steel_member = db.relationship('SteelMember', backref=db.backref('reports', lazy=True))

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
    if current_user.role.name != 'Admin':
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

@app.route('/admin/roles', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
def view_roles():
    roles = Role.query.all()
    return render_template('view_roles.html', roles=roles)

@app.route('/admin/create_role', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def create_role():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        access_values = request.form['access_values']
        create_reports = request.form['create_reports']
        can_access_fabrication = request.form['can_access_fabrication']
        can_edit_fabrication = request.form['can_edit_fabrication']
        role = Role(name=name, description=description, access_values=access_values,
                    create_reports=create_reports, can_access_fabrication=can_access_fabrication,
                    can_edit_fabrication=can_edit_fabrication)
        db.session.add(role)
        db.session.commit()
        flash('Role created successfully!', 'success')
        return redirect(url_for('view_roles'))
    return render_template('create_role.html')

@app.route('/admin/edit_role/<int:role_id>', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def edit_role(role_id):
    role = Role.query.get_or_404(role_id)
    if request.method == 'POST':
        role.name = request.form['name']
        role.description = request.form['description']
        role.access_values = request.form['access_values']
        role.create_reports = request.form['create_reports']
        db.session.commit()
        flash('Role updated successfully!', 'success')
        return redirect(url_for('view_roles'))
    return render_template('edit_role.html', role=role)

@app.route('/admin/delete_role/<int:role_id>', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    db.session.delete(role)
    db.session.commit()
    flash('Role deleted successfully!', 'success')
    return redirect(url_for('view_roles'))

@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
#@project_manager_permission.require(http_exception=403)
def create_project():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        status = request.form['status']
        project = Project(name=name, description=description, start_date=start_date, end_date=end_date, status=status)
        db.session.add(project)
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('dashboard'))#url_for('view_projects')
    return render_template('create_project.html')
"""
@app.route('/create_project', methods=['GET', 'POST'])
@login_required  # Assuming only logged-in users can create projects
def create_project():
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(name=form.name.data)
        db.session.add(project)
        db.session.commit()
        flash('Project successfully created!', 'success')
        return redirect(url_for('dashboard'))  # Or wherever you want to redirect after creating a project
    return render_template('create_project.html', form=form)
"""
@app.route('/projects')
@login_required
#@project_manager_permission.require(http_exception=403)
def view_projects():
    projects = Project.query.all()
    return render_template('view_projects.html', projects=projects)

class SteelMemberForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    dispatch_date = DateField('Dispatch Date', format='%Y-%m-%d')
    delivery_date = DateField('Delivery Date', format='%Y-%m-%d')
    installation_date = DateField('Installation Date', format='%Y-%m-%d')
    submit = SubmitField('Add Member')
    delivery_date = DateField('Delivery Date', validators=[Optional()])
    installation_date = DateField('Installation Date', validators=[Optional()])

@app.route('/add_member/<int:project_id>', methods=['GET', 'POST'])
@login_required
def add_member(project_id):
    project = Project.query.get_or_404(project_id)
    form = SteelMemberForm()
    
    if current_user.role.name not in ['Admin', 'Editor']:
        flash('You do not have permission to perform this action.', 'danger')
        print("Redirecting due to insufficient role.")
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        member = SteelMember(name=form.name.data, 
                             dispatch_date=form.dispatch_date.data,
                             delivery_date=form.delivery_date.data,
                             installation_date=form.installation_date.data,
                             user_id=current_user.id)
        member.project_id = project.id
        db.session.add(member)
        db.session.commit()
        flash('Steel member added successfully!', 'success')
        print("Steel member added successfully!")
        return redirect(url_for('dashboard'))
    else:
        print("Form did not validate.")
        print(form.errors)  # This will print the form errors to the console

    return render_template('add_member.html', form=form, project=project)


@app.route('/view_members/<int:project_id>')
@login_required
def view_members(project_id):
    project = Project.query.get_or_404(project_id)
    members = SteelMember.query.filter_by(project_id=project_id).all()
    return render_template('view_members.html', project=project, members=members)


@app.route('/edit_member/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_member(id):
    member = SteelMember.query.get_or_404(id)
    form = SteelMemberForm(obj=member)
    if current_user.role.name not in ['Admin', 'Editor']:
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


# Update fabrication status
@app.route('/update_fabrication/<int:member_id>', methods=['GET', 'POST'])
@login_required
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

# Update receive status
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

@app.route('/update_installation_steps/<int:member_id>', methods=['GET', 'POST'])
@login_required
def update_installation_steps(member_id):
    # Implement logic to update installation steps
 return render_template('update_installation_steps.html')

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
    current_project_id = session.get('current_project_id')
    if not current_project_id:
        flash('Please select a project first', 'warning')
        return redirect(url_for('select_project'))
    current_project = db.session.get(Project, current_project_id)
    if not current_project:
        flash('Project not found', 'error')
        return redirect(url_for('select_project'))  # or some other appropriate route

    search_name = request.args.get('search_name')
    from_dispatch_date = request.args.get('from_dispatch_date')
    to_dispatch_date = request.args.get('to_dispatch_date')
    # Add logic for other search criteria
   # has_permission = current_user.has_permission('view_reports')
    query = SteelMember.query

    if search_name:
        query = query.filter(SteelMember.name.contains(search_name))
    if from_dispatch_date and to_dispatch_date:
        query = query.filter(SteelMember.dispatch_date.between(from_dispatch_date, to_dispatch_date))
    # Add logic for other search criteria

    members = query.all()
    return render_template('dashboard.html', current_project=current_project, members=members)#, gantt_chart=gantt_chart, percentage_completion_chart=percentage_completion_chart, delivery_rate_chart=delivery_rate_chart
   

@app.route('/generate_report', methods=['GET', 'POST'])
def generate_report():
    if request.method == 'POST':
        department = request.form.get('department')
        report_type = request.form.get('report_type')
        
        content = f"Report for {department} - {report_type}\n\n"
        
        if report_type == 'Delivery Note':
            # Fetch all steel members dispatched on a particular date
            dispatch_date = request.form.get('date')
            steel_members = SteelMember.query.filter_by(dispatch_date=dispatch_date).all()
            for member in steel_members:
                content += f"Member ID: {member.id}, Name: {member.name}, Dispatch Date: {member.dispatch_date}\n"
        
        elif report_type == 'Fabrication Release':
            # Fetch all steel members fabricated within a date range
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            steel_members = SteelMember.query.filter(SteelMember.fabrication_date.between(start_date, end_date)).all()
            for member in steel_members:
                content += f"Member ID: {member.id}, Name: {member.name}, Fabrication Date: {member.fabrication_date}\n"
        
        # ... handle other report types ...

        # Store the generated report in the database
        report = Report(department=department, report_type=report_type, content=content)
        db.session.add(report)
        db.session.commit()
        
        flash('Report generated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('generate_report.html')

@app.route('/update_dispatch_date/<int:member_id>', methods=['POST'])
def update_dispatch_date(member_id):
    member = SteelMember.query.get_or_404(member_id)
    member.dispatch_date = request.form.get('dispatch_date')
    db.session.commit()
    
    # Automatically generate a "Delivery Note" report after updating the dispatch date
    content = f"Delivery Note for {member.name}\n\nDispatch Date: {member.dispatch_date}"
    report = Report(department='Dispatch', report_type='Delivery Note', content=content)
    db.session.add(report)
    db.session.commit()
    
    flash('Dispatch date updated and Delivery Note generated!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/select_project', methods=['GET', 'POST'])
@login_required
def select_project():
    if request.method == 'POST':
        project_id = request.form.get('selected_project')
        session['current_project_id'] = project_id
        return redirect(url_for('dashboard'))
    
    projects = Project.query.all()
    return render_template('select_project.html', projects=projects)

@app.route('/set_current_project', methods=['POST'])
def set_current_project():
    project_name = request.form.get('project_name')
    project = Project.query.filter_by(name=project_name).first()
    if project:
        session['current_project_id'] = project.id
        return redirect(url_for('dashboard'))
    else:
        flash('Please select a valid project.', 'danger')
        return redirect(url_for('select_project'))
   
@app.route('/reports')
@login_required
def list_reports():
    reports = Report.query.all()
    return render_template('list_reports.html', reports=reports)

@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    report = Report.query.get_or_404(report_id)
    return render_template('view_report.html', report=report)


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

# Generate Gantt Chart
@app.route('/generate_gantt_chart/<int:project_id>')
@login_required
def generate_gantt_chart(project_id):
    project = Project.query.get_or_404(project_id)
    members = project.members

    fig, ax = plt.subplots(figsize=(10, len(members)))

    for index, member in enumerate(members):
        start_date = member.dispatch_date if member.dispatch_date else date.today()
        end_date = member.installation_date if member.installation_date else start_date + timedelta(days=7)  # Default duration is set to 7 days
        ax.barh(index, (end_date - start_date).days, left=start_date, align='center', label=member.name)

    ax.set_yticks(range(len(members)))
    ax.set_yticklabels([member.name for member in members])
    ax.set_xlabel('Timeline')
    ax.set_title(f'Gantt Chart for Project {project.name}')
    plt.tight_layout()

    img_path = os.path.join('static', 'gantt_chart.png')
    plt.savefig(img_path)
    plt.close(fig)

    return render_template('gantt_chart.html', img_path=img_path)

# Generate Percentage Completion Chart
@app.route('/generate_percentage_completion_chart_route/<int:project_id>')
@login_required
def generate_percentage_completion_chart_route(project_id):
    project = Project.query.get_or_404(project_id)
    members = project.members

    total_members = len(members)
    dispatched = len([member for member in members if member.dispatch_date])
    delivered = len([member for member in members if member.delivery_date])
    installed = len([member for member in members if member.installation_date])

    labels = ['Dispatched', 'Delivered', 'Installed']
    values = [dispatched, delivered, installed]
    colors = ['#FF9999', '#66B2FF', '#99FF99']

    fig, ax = plt.subplots()
    ax.pie(values, labels=labels, colors=colors, startangle=90, autopct='%1.1f%%')
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title(f'Percentage Completion Chart for Project {project.name}')

    img_path = os.path.join('static', 'percentage_completion_chart.png')
    plt.savefig(img_path)
    plt.close(fig)

    return render_template('percentage_completion_chart.html', img_path=img_path)

# Generate Delivery Rate Chart
@app.route('/generate_delivery_rate_chart_route/<int:project_id>')
@login_required
def generate_delivery_rate_chart_route(project_id):
    project = Project.query.get_or_404(project_id)
    members = project.members

    dispatch_dates = [member.dispatch_date for member in members if member.dispatch_date]
    delivery_dates = [member.delivery_date for member in members if member.delivery_date]
    installation_dates = [member.installation_date for member in members if member.installation_date]

    date_range = [date.today() - timedelta(days=i) for i in range(30)]  # Last 30 days
    dispatch_counts = [len([d for d in dispatch_dates if d == day]) for day in date_range]
    delivery_counts = [len([d for d in delivery_dates if d == day]) for day in date_range]
    installation_counts = [len([d for d in installation_dates if d == day]) for day in date_range]

    fig, ax = plt.subplots()
    ax.plot(date_range, dispatch_counts, '-b', label='Dispatched')
    ax.plot(date_range, delivery_counts, '-r', label='Delivered')
    ax.plot(date_range, installation_counts, '-g', label='Installed')
    ax.set_xlabel('Date')
    ax.set_ylabel('Number of Steel Members')
    ax.set_title(f'Delivery Rate Chart for Project {project.name}')
    ax.legend(loc='upper left')
    fig.autofmt_xdate()

    img_path = os.path.join('static', 'delivery_rate_chart.png')
    plt.savefig(img_path)
    plt.close(fig)

    return render_template('delivery_rate_chart.html', img_path=img_path)

@app.route('/generate_custom_report', methods=['GET', 'POST'])
@login_required
def generate_custom_report():
    form = CustomReportForm()
    if form.validate_on_submit():
        # Generate the custom report based on selected fields and parameters
        # ...
        return redirect(url_for('view_report', report_id=report.id))
    return render_template('custom_report_form.html', form=form)

if __name__ == '__main__':
    app.run(debug=True) 
   



