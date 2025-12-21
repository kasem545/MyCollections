/*  HackPad - A simple note-taking application 
    created for penetration testers.
    can be compiled with: gcc HackPad.c -lncurses -o HackPad
    Copyright (C) 2025  <Kasem Shibli> <kasem545@proton.me>
*/

#include <ncurses.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#define MAX_SECTIONS 16
#define MAX_ENTRIES  512
#define MAX_TEXT     512
#define MAX_NAME     64

typedef struct {
    char text[MAX_TEXT];
    time_t timestamp;
} Entry;

typedef struct {
    char name[MAX_NAME];
    Entry entries[MAX_ENTRIES];
    int entry_count;
    int selected_entry;
    int scroll_offset;
} Section;

typedef enum {
    FOCUS_SECTIONS,
    FOCUS_ENTRIES
} Focus;

typedef struct {
    Section sections[MAX_SECTIONS];
    int section_count;
    int current_section;
    Focus focus;
    char filename[256];
} HackPad;

/* ---------------- UI ---------------- */

void ui_init(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    set_escdelay(25);
    curs_set(0);
    
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN, -1);
        init_pair(2, COLOR_YELLOW, -1);
        init_pair(3, COLOR_CYAN, -1);
    }
    
    refresh();
}

void ui_shutdown(void) {
    endwin();
}

void status_msg(const char *msg) {
    if (has_colors()) attron(COLOR_PAIR(2));
    mvprintw(LINES - 1, 0, "%s", msg);
    clrtoeol();
    if (has_colors()) attroff(COLOR_PAIR(2));
    refresh();
}

/* ---------------- SAVE/LOAD ---------------- */

void save_HackPad(HackPad *nb, const char *file) {
    FILE *f = fopen(file, "w");
    if (!f) {
        status_msg("ERROR: Could not save file!");
        return;
    }

    time_t now = time(NULL);
    fprintf(f, "# Pentesting HackPad\n");
    fprintf(f, "Generated: %s\n", ctime(&now));

    for (int i = 0; i < nb->section_count; i++) {
        fprintf(f, "\n## %s\n\n", nb->sections[i].name);
        for (int j = 0; j < nb->sections[i].entry_count; j++) {
            char ts[64];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S",
                    localtime(&nb->sections[i].entries[j].timestamp));
            fprintf(f, "- [%s] %s\n", ts, nb->sections[i].entries[j].text);
        }
    }
    fclose(f);
    status_msg("Saved successfully!");
}

void load_HackPad(HackPad *nb, const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) return;

    char line[MAX_TEXT + 128];
    int cur_sec = -1;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;

        if (strncmp(line, "## ", 3) == 0 && nb->section_count < MAX_SECTIONS) {
            cur_sec = nb->section_count++;
            strncpy(nb->sections[cur_sec].name, line + 3, MAX_NAME - 1);
            nb->sections[cur_sec].entry_count = 0;
            nb->sections[cur_sec].selected_entry = 0;
            nb->sections[cur_sec].scroll_offset = 0;
        }
        else if (cur_sec >= 0 && strncmp(line, "- ", 2) == 0) {
            Section *s = &nb->sections[cur_sec];
            if (s->entry_count >= MAX_ENTRIES) continue;

            char *txt = line + 2;
            if (line[2] == '[') {
                char *end = strchr(line + 3, ']');
                if (end && end[1] == ' ') txt = end + 2;
            }

            strncpy(s->entries[s->entry_count].text, txt, MAX_TEXT - 1);
            s->entries[s->entry_count].timestamp = time(NULL);
            s->entry_count++;
        }
    }
    fclose(f);
}

/* ---------------- DRAW ---------------- */

void draw_sections(WINDOW *w, HackPad *nb) {
    werase(w);
    box(w, 0, 0);
    
    if (has_colors()) wattron(w, COLOR_PAIR(1) | A_BOLD);
    mvwprintw(w, 0, 2, " SECTIONS ");
    if (has_colors()) wattroff(w, COLOR_PAIR(1) | A_BOLD);

    for (int i = 0; i < nb->section_count; i++) {
        if (nb->focus == FOCUS_SECTIONS && i == nb->current_section)
            wattron(w, A_REVERSE);

        mvwprintw(w, i + 1, 2, "%-15s (%d)", nb->sections[i].name,
                  nb->sections[i].entry_count);

        if (nb->focus == FOCUS_SECTIONS && i == nb->current_section)
            wattroff(w, A_REVERSE);
    }
    
    if (has_colors()) wattron(w, COLOR_PAIR(2));
    mvwprintw(w, getmaxy(w) - 2, 2, "N:New D:Del");
    if (has_colors()) wattroff(w, COLOR_PAIR(2));
    
    wrefresh(w);
}

void draw_entries(WINDOW *w, HackPad *nb) {
    Section *s = &nb->sections[nb->current_section];
    int max_y = getmaxy(w) - 4;

    werase(w);
    box(w, 0, 0);
    
    if (has_colors()) wattron(w, COLOR_PAIR(1) | A_BOLD);
    mvwprintw(w, 0, 2, " %s ", s->name);
    if (has_colors()) wattroff(w, COLOR_PAIR(1) | A_BOLD);

    if (s->selected_entry < s->scroll_offset)
        s->scroll_offset = s->selected_entry;
    if (s->selected_entry >= s->scroll_offset + max_y)
        s->scroll_offset = s->selected_entry - max_y + 1;

    for (int i = 0; i < max_y && (i + s->scroll_offset) < s->entry_count; i++) {
        int idx = i + s->scroll_offset;
        
        if (nb->focus == FOCUS_ENTRIES && idx == s->selected_entry)
            wattron(w, A_REVERSE);

        mvwprintw(w, i + 1, 2, "%s", s->entries[idx].text);

        if (nb->focus == FOCUS_ENTRIES && idx == s->selected_entry)
            wattroff(w, A_REVERSE);
    }

    if (s->entry_count > max_y) {
        if (has_colors()) wattron(w, COLOR_PAIR(3));
        mvwprintw(w, 1, getmaxx(w) - 3, "^");
        mvwprintw(w, getmaxy(w) - 3, getmaxx(w) - 3, "v");
        if (has_colors()) wattroff(w, COLOR_PAIR(3));
    }

    if (has_colors()) wattron(w, COLOR_PAIR(2));
    mvwprintw(w, getmaxy(w) - 2, 2,
        "</> Focus  ^/v Nav | A:Add E:Edit D:Del C:Copy S:Save W:SaveAs Q:Quit");
    if (has_colors()) wattroff(w, COLOR_PAIR(2));

    wrefresh(w);
}

/* ---------------- LINE EDITOR ---------------- */

int line_editor(const char *title, char *buf, int max_len) {
    int h = 7, w = COLS - 6;
    int y = (LINES - h) / 2, x = 3;

    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);
    keypad(win, TRUE);
    curs_set(1);

    mvwprintw(win, 0, 2, " %s ", title);
    mvwprintw(win, 4, 2, "Enter:Save  ESC:Cancel");

    int len = strlen(buf);
    int cur = len;
    int ch;

    while (1) {
        werase(win);
        box(win, 0, 0);
        mvwprintw(win, 0, 2, " %s ", title);
        mvwprintw(win, 2, 2, "%s", buf);
        mvwprintw(win, 4, 2, "Enter:Save  ESC:Cancel");
        wmove(win, 2, 2 + cur);
        wrefresh(win);

        ch = wgetch(win);

        if (ch == 27) { 
            delwin(win);
            curs_set(0);
            return 0;
        }
        if (ch == '\n') {
            delwin(win);
            curs_set(0);
            return buf[0] != '\0';
        }
        if (ch == KEY_LEFT && cur > 0) 
            cur--;
        else if (ch == KEY_RIGHT && cur < len) 
            cur++;
        else if (ch == KEY_HOME)
            cur = 0;
        else if (ch == KEY_END)
            cur = len;
        else if ((ch == KEY_BACKSPACE || ch == 127 || ch == 8) && cur > 0) {
            memmove(&buf[cur - 1], &buf[cur], len - cur + 1);
            cur--; len--;
        }
        else if (ch == KEY_DC && cur < len) {
            memmove(&buf[cur], &buf[cur + 1], len - cur);
            len--;
        }
        else if (isprint(ch) && len < max_len - 1) {
            memmove(&buf[cur + 1], &buf[cur], len - cur + 1);
            buf[cur++] = ch;
            len++;
        }
    }
}

int confirm_dialog(const char *msg) {
    int h = 5, w = 50;
    int y = (LINES - h) / 2, x = (COLS - w) / 2;

    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);
    
    mvwprintw(win, 1, 2, "%s", msg);
    mvwprintw(win, 3, 2, "Y:Yes  N:No");
    wrefresh(win);
    
    int ch = getch();
    delwin(win);
    
    return (ch == 'y' || ch == 'Y');
}

/* ---------------- ACTIONS ---------------- */

void add_section(HackPad *nb) {
    if (nb->section_count >= MAX_SECTIONS) {
        status_msg("ERROR: Max sections reached!");
        return;
    }

    char buf[MAX_NAME] = {0};
    if (line_editor("New Section", buf, MAX_NAME)) {
        Section *s = &nb->sections[nb->section_count];
        strncpy(s->name, buf, MAX_NAME - 1);
        s->entry_count = 0;
        s->selected_entry = 0;
        s->scroll_offset = 0;
        nb->current_section = nb->section_count;
        nb->section_count++;
        nb->focus = FOCUS_SECTIONS;
        status_msg("Section created!");
    }
}

void add_entry(HackPad *nb) {
    Section *s = &nb->sections[nb->current_section];
    if (s->entry_count >= MAX_ENTRIES) {
        status_msg("ERROR: Max entries reached!");
        return;
    }

    char buf[MAX_TEXT] = {0};
    if (line_editor("New Entry", buf, MAX_TEXT)) {
        strncpy(s->entries[s->entry_count].text, buf, MAX_TEXT - 1);
        s->entries[s->entry_count].timestamp = time(NULL);
        s->selected_entry = s->entry_count;
        s->entry_count++;
        nb->focus = FOCUS_ENTRIES;
        status_msg("Entry added!");
    }
}

void edit_entry(HackPad *nb) {
    Section *s = &nb->sections[nb->current_section];
    if (!s->entry_count) {
        status_msg("No entries to edit!");
        return;
    }

    char buf[MAX_TEXT];
    strncpy(buf, s->entries[s->selected_entry].text, MAX_TEXT - 1);

    if (line_editor("Edit Entry", buf, MAX_TEXT)) {
        strncpy(s->entries[s->selected_entry].text, buf, MAX_TEXT - 1);
        s->entries[s->selected_entry].timestamp = time(NULL);
        status_msg("Entry updated!");
    }
}

void delete_section(HackPad *nb) {
    if (nb->section_count <= 1) {
        status_msg("Cannot delete the last section!");
        return;
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "Delete section '%s' and all its entries?", 
             nb->sections[nb->current_section].name);
    
    if (!confirm_dialog(msg)) {
        status_msg("Cancelled");
        return;
    }

    for (int i = nb->current_section; i < nb->section_count - 1; i++)
        nb->sections[i] = nb->sections[i + 1];

    nb->section_count--;
    
    if (nb->current_section >= nb->section_count)
        nb->current_section = nb->section_count - 1;
    
    status_msg("Section deleted!");
}

void delete_entry(HackPad *nb) {
    Section *s = &nb->sections[nb->current_section];
    if (!s->entry_count) {
        status_msg("No entries to delete!");
        return;
    }

    if (!confirm_dialog("Delete this entry?")) {
        status_msg("Cancelled");
        return;
    }

    for (int i = s->selected_entry; i < s->entry_count - 1; i++)
        s->entries[i] = s->entries[i + 1];

    s->entry_count--;
    if (s->selected_entry >= s->entry_count && s->entry_count > 0)
        s->selected_entry--;
    
    status_msg("Entry deleted!");
}

void copy_to_clipboard(HackPad *nb) {
    Section *s = &nb->sections[nb->current_section];
    if (!s->entry_count) {
        status_msg("No entries to copy!");
        return;
    }

    FILE *clip = popen("xclip -selection clipboard 2>/dev/null || "
                       "xsel --clipboard 2>/dev/null || "
                       "pbcopy 2>/dev/null || "
                       "wl-copy 2>/dev/null", "w");
    
    if (clip) {
        fprintf(clip, "%s", s->entries[s->selected_entry].text);
        int result = pclose(clip);
        if (result == 0) {
            status_msg("Copied to clipboard!");
            return;
        }
    }
    
    if (s->entry_count >= MAX_ENTRIES) {
        status_msg("ERROR: Max entries reached!");
        return;
    }
    
    s->entries[s->entry_count] = s->entries[s->selected_entry];
    s->entries[s->entry_count].timestamp = time(NULL);
    s->selected_entry = s->entry_count;
    s->entry_count++;
    status_msg("Clipboard unavailable - entry duplicated instead");
}

void quick_save(HackPad *nb) {
    save_HackPad(nb, nb->filename);
}

void save_as(HackPad *nb) {
    char newfile[256] = {0};
    strncpy(newfile, nb->filename, 255);
    
    if (line_editor("Save As", newfile, 256)) {
        strncpy(nb->filename, newfile, 255);
        save_HackPad(nb, nb->filename);
    }
}

/* ---------------- MAIN ---------------- */

int main(int argc, char *argv[]) {
    HackPad nb = {0};
    nb.focus = FOCUS_SECTIONS;
    
    const char *file = (argc > 1) ? argv[1] : "HackPad.md";

    load_HackPad(&nb, file);
    strncpy(nb.filename, file, 255);

    if (nb.section_count == 0) {
        nb.section_count = 4;
        strcpy(nb.sections[0].name, "Hosts");
        strcpy(nb.sections[1].name, "Credentials");
        strcpy(nb.sections[2].name, "Exploits");
        strcpy(nb.sections[3].name, "Notes");
    }

    ui_init();

    int sw = 25;
    WINDOW *sec = newwin(LINES - 1, sw, 0, 0);
    WINDOW *ent = newwin(LINES - 1, COLS - sw, 0, sw);

    keypad(sec, TRUE);
    keypad(ent, TRUE);

    draw_sections(sec, &nb);
    draw_entries(ent, &nb);
    status_msg("Ready. Press Q to quit");

    int ch;
    while ((ch = getch()) != 'q' && ch != 'Q') {
        Section *s = &nb.sections[nb.current_section];

        switch (ch) {
            case KEY_LEFT:  
            case 'h':
                nb.focus = FOCUS_SECTIONS; 
                break;
                
            case KEY_RIGHT: 
            case 'l':
                nb.focus = FOCUS_ENTRIES; 
                break;

            case KEY_UP:
            case 'k':
                if (nb.focus == FOCUS_SECTIONS && nb.current_section > 0)
                    nb.current_section--;
                else if (nb.focus == FOCUS_ENTRIES && s->selected_entry > 0)
                    s->selected_entry--;
                break;

            case KEY_DOWN:
            case 'j':
                if (nb.focus == FOCUS_SECTIONS &&
                    nb.current_section < nb.section_count - 1)
                    nb.current_section++;
                else if (nb.focus == FOCUS_ENTRIES &&
                         s->selected_entry < s->entry_count - 1)
                    s->selected_entry++;
                break;

            case KEY_PPAGE:
                if (nb.focus == FOCUS_ENTRIES && s->entry_count > 0) {
                    s->selected_entry = (s->selected_entry > 10) ?
                        s->selected_entry - 10 : 0;
                }
                break;

            case KEY_NPAGE:
                if (nb.focus == FOCUS_ENTRIES && s->entry_count > 0) {
                    s->selected_entry = (s->selected_entry + 10 < s->entry_count) ?
                        s->selected_entry + 10 : s->entry_count - 1;
                }
                break;

            case 'n':
            case 'N': 
                add_section(&nb); 
                break;
                
            case 'a':
            case 'A': 
                add_entry(&nb); 
                break;
                
            case 'e':
            case 'E': 
                edit_entry(&nb); 
                break;
                
            case 'd':
            case 'D': 
                if (nb.focus == FOCUS_SECTIONS)
                    delete_section(&nb);
                else
                    delete_entry(&nb); 
                break;
                
            case 'c':
            case 'C': 
                copy_to_clipboard(&nb); 
                break;
                
            case 's':
            case 'S': 
                quick_save(&nb); 
                break;
                
            case 'w':
            case 'W':
                save_as(&nb);
                break;
        }

        draw_sections(sec, &nb);
        draw_entries(ent, &nb);
    }

    if (confirm_dialog("Save before quitting?")) {
        save_HackPad(&nb, nb.filename);
    }

    ui_shutdown();
    //printf("HackPad: %s\n", nb.filename);
    return 0;
}
