from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan/', views.scan_form, name='scan_form'),
    path('scan/submit/', views.submit_scan, name='submit_scan'),
    path('reports/', views.reports_list, name='reports_list'),
    path('reports/<int:report_id>/', views.report_detail, name='report_detail'),
    path('reports/delete/<int:report_id>/', views.delete_report, name='delete_report'),
    path('api/scan-status/<int:report_id>/', views.scan_status, name='scan_status'),
]