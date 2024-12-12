# from django.contrib import admin
# from parkeasy.models import User
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# class UserModelAdmin(BaseUserAdmin):
# 	#these fields override the definitions on the base UserModelAdmin
# 	list_display = ["id", "email", "name", "tc", "is_admin", "is_staff"]
# 	list_filter = ["is_admin", "is_staff", "is_active"]

# 	fieldsets = [
# 		("User Credentials", {"fields" : ["email", "password"]}),
# 		("Personal info", {"fields" : ["name", "tc"]}),
# 		("Permissions", {"fields" : ["is_admin"]}),
# 	]

# 	"""
# 	Add fieldsets is not a standard ModelAdmin attribute.
# 	UserModelAdmin overrides get_fieldsets to use this attribute when creating user
# 	"""
# 	add_fieldsets = [
# 		#here none specifies no title or heading
# 		(
# 			None, 
# 			{
# 				"classes" : ["wide"],
# 				"fields" : ["email", "name", "tc", "password1", "password2", ]
# 			},
# 		),
# 	]

# 	search_fields = ["email"]
# 	ordering = ["email","id"]
# 	filter_horizontal = []

# admin.site.register(User, UserModelAdmin)