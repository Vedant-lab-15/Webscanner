from django.contrib import admin
from .models import VulnerabilityType, ScanReport, Vulnerability

@admin.register(VulnerabilityType)
class VulnerabilityTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'created_at')
    list_filter = ('severity',)
    search_fields = ('name', 'description')

class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0
    readonly_fields = ('vulnerability_type', 'line_number', 'column', 'payload', 'context')

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'url', 'scan_date', 'status')
    list_filter = ('status', 'scan_date')
    search_fields = ('url',)
    readonly_fields = ('scan_date',)
    inlines = [VulnerabilityInline]

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('vulnerability_type', 'report', 'line_number')
    list_filter = ('vulnerability_type__severity', 'vulnerability_type')
    search_fields = ('report__url', 'payload', 'description')