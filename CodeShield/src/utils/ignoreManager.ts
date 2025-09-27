import * as vscode from 'vscode';

export class IgnoreManager {
    private static readonly IGNORE_KEY = 'codeshield.ignoredVulnerabilities';
    
    /**
     * Add vulnerability to ignore list
     */
    static async addToIgnoreList(
        document: vscode.TextDocument, 
        line: number, 
        vulnerabilityType: string
    ): Promise<void> {
        const workspaceState = this.getWorkspaceState();
        const ignored = workspaceState.get<IgnoredVulnerability[]>(this.IGNORE_KEY, []);
        
        const fileUri = document.uri.toString();
        const newIgnored: IgnoredVulnerability = {
            fileUri,
            line,
            vulnerabilityType,
            ignoredAt: Date.now()
        };
        
        // Check if already ignored
        const exists = ignored.some(item => 
            item.fileUri === fileUri && 
            item.line === line && 
            item.vulnerabilityType === vulnerabilityType
        );
        
        if (!exists) {
            ignored.push(newIgnored);
            await workspaceState.update(this.IGNORE_KEY, ignored);
        }
    }
    
    /**
     * Check if vulnerability is ignored
     */
    static isIgnored(
        document: vscode.TextDocument, 
        line: number, 
        vulnerabilityType: string
    ): boolean {
        const workspaceState = this.getWorkspaceState();
        const ignored = workspaceState.get<IgnoredVulnerability[]>(this.IGNORE_KEY, []);
        
        const fileUri = document.uri.toString();
        return ignored.some(item => 
            item.fileUri === fileUri && 
            item.line === line && 
            item.vulnerabilityType === vulnerabilityType
        );
    }
    
    /**
     * Remove from ignore list
     */
    static async removeFromIgnoreList(
        document: vscode.TextDocument, 
        line: number, 
        vulnerabilityType: string
    ): Promise<void> {
        const workspaceState = this.getWorkspaceState();
        const ignored = workspaceState.get<IgnoredVulnerability[]>(this.IGNORE_KEY, []);
        
        const fileUri = document.uri.toString();
        const filtered = ignored.filter(item => 
            !(item.fileUri === fileUri && 
              item.line === line && 
              item.vulnerabilityType === vulnerabilityType)
        );
        
        await workspaceState.update(this.IGNORE_KEY, filtered);
    }
    
    /**
     * Get all ignored vulnerabilities
     */
    static getIgnoredList(): IgnoredVulnerability[] {
        const workspaceState = this.getWorkspaceState();
        return workspaceState.get<IgnoredVulnerability[]>(this.IGNORE_KEY, []);
    }
    
    /**
     * Clear all ignored vulnerabilities
     */
    static async clearIgnoreList(): Promise<void> {
        const workspaceState = this.getWorkspaceState();
        await workspaceState.update(this.IGNORE_KEY, []);
    }
    
    private static workspaceState: vscode.Memento;
    
    static initialize(context: vscode.ExtensionContext): void {
        this.workspaceState = context.workspaceState;
    }
    
    private static getWorkspaceState(): vscode.Memento {
        if (!this.workspaceState) {
            throw new Error('IgnoreManager not initialized');
        }
        return this.workspaceState;
    }
}

export interface IgnoredVulnerability {
    fileUri: string;
    line: number;
    vulnerabilityType: string;
    ignoredAt: number;
}